//
// Copyright (c) 2026 whawty contributors (see AUTHORS file)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// * Neither the name of whawty.auth nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// storeFiles returns all files in the store except .tmp, with their contents.
func storeFiles(t *testing.T, d *Dir) map[string]string {
	t.Helper()
	files := make(map[string]string)
	err := filepath.WalkDir(d.BaseDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(d.BaseDir, path)
		if rel == tmpDir {
			return filepath.SkipDir
		}
		if !entry.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files[rel] = string(data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestMigrate(t *testing.T) {
	d := newHardeningTestDir(t) // root is an admin in format v1
	mustAdd(t, d, "alice", "alicepw", false)
	mustAdd(t, d, "bob@example.com", "bobpw", true)
	extra := map[string]string{".hidden": "x", "-invalid.user": "x"}
	for name, content := range extra {
		if err := os.WriteFile(filepath.Join(d.BaseDir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	before := storeFiles(t, d)

	migrated, err := d.Migrate()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(migrated)
	if want := []string{"alice", "bob@example.com", "root"}; !reflect.DeepEqual(migrated, want) {
		t.Fatalf("migrated %v, expected %v", migrated, want)
	}

	expected := map[string]string{
		"root/hash": before["root.admin"], "root/admin": "",
		"alice/hash":           before["alice.user"],
		"bob@example.com/hash": before["bob@example.com.admin"], "bob@example.com/admin": "",
	}
	for name, content := range extra {
		expected[name] = content // left alone
	}
	if after := storeFiles(t, d); !reflect.DeepEqual(after, expected) {
		t.Fatalf("store after migration:\n%v\nexpected:\n%v", after, expected)
	}
	mustAuthenticate(t, d, "root", "secret")
	mustAuthenticate(t, d, "alice", "alicepw")
	if _, isAdmin, _ := d.Exists("bob@example.com"); !isAdmin {
		t.Fatal("bob lost admin status")
	}
	if err := d.Check(); err != nil {
		t.Fatal(err)
	}

	// the store has been migrated, new users get a directory
	mustAdd(t, d, "carol", "pw", false)
	if _, err := os.Stat(filepath.Join(d.BaseDir, "carol", hashFile)); err != nil {
		t.Fatalf("new user after migration isn't stored in format v2: %v", err)
	}
	if migrated, err := d.Migrate(); err != nil || len(migrated) != 0 {
		t.Fatalf("second migration: %v, %v", migrated, err)
	}
}

// User names may contain dots, so a directory may need the name of the v1 file of another user.
func TestMigrateNameCollision(t *testing.T) {
	d := newHardeningTestDir(t)
	for _, name := range []string{"a.user.user", "a.user", "a", "a.admin"} {
		mustAdd(t, d, name, name+"-pw", false)
	}
	if err := d.SetAdmin("a", true); err != nil { // its file a.admin collides with user a.admin
		t.Fatal(err)
	}
	if _, err := d.Migrate(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.user.user", "a.user", "a", "a.admin"} {
		mustAuthenticate(t, d, name, name+"-pw")
		if info, err := os.Stat(filepath.Join(d.BaseDir, name)); err != nil || !info.IsDir() {
			t.Fatalf("'%s' is no user directory: %v", name, err)
		}
	}
	if _, isAdmin, _ := d.Exists("a"); !isAdmin {
		t.Fatal("a lost admin status")
	}
}

// A user that already has a directory from an interrupted migration keeps it.
func TestMigrateResumes(t *testing.T) {
	d := newHardeningTestDir(t)
	mustAdd(t, d, "alice", "old", false)
	putV2User(t, d, "alice", "new", false, nil)

	if migrated, err := d.Migrate(); err != nil || len(migrated) != 2 {
		t.Fatalf("migrate: %v, %v", migrated, err)
	}
	mustAuthenticate(t, d, "alice", "new")
	if _, err := os.Stat(filepath.Join(d.BaseDir, "alice.user")); !os.IsNotExist(err) {
		t.Fatalf("v1 file still exists: %v", err)
	}
}

func TestMigrateRefuses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, d *Dir)
		err   string
	}{
		{"aux data", func(t *testing.T, d *Dir) { appendAuxData(t, filepath.Join(d.BaseDir, "alice.user")) }, "auxiliary data"},
		{"duplicate", func(t *testing.T, d *Dir) {
			if err := os.WriteFile(filepath.Join(d.BaseDir, "alice.admin"), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		}, "both"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newHardeningTestDir(t)
			mustAdd(t, d, "alice", "pw", false)
			tc.setup(t, d)
			before := storeFiles(t, d)
			if _, err := d.Migrate(); err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("migrate returned: %v", err)
			}
			if after := storeFiles(t, d); !reflect.DeepEqual(after, before) {
				t.Fatalf("migrate changed the store although it failed:\n%v\nbefore:\n%v", after, before)
			}
		})
	}
}

// Logins must keep working while a store gets migrated.
func TestReadersDuringMigrate(t *testing.T) {
	d := newHardeningTestDir(t)
	line := testHashLine(t, d, "pw")
	const n = 300
	for i := 0; i < n; i++ {
		putV1Line(t, d, fmt.Sprintf("user%d", i), line, i%3 == 0)
	}

	var wg sync.WaitGroup
	done := make(chan struct{})
	failed := make(chan string, 1)
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			for i := r; ; i = (i + 7) % n {
				select {
				case <-done:
					return
				default:
				}
				user := fmt.Sprintf("user%d", i)
				if exists, isAdmin, err := d.Exists(user); !exists || err != nil || isAdmin != (i%3 == 0) {
					select {
					case failed <- fmt.Sprintf("%s: exists=%v admin=%v err=%v", user, exists, isAdmin, err):
					default:
					}
				}
			}
		}(r)
	}
	migrated, err := d.Migrate()
	close(done)
	wg.Wait()
	if err != nil || len(migrated) != n+1 {
		t.Fatalf("migrate: %d users, %v", len(migrated), err)
	}
	select {
	case msg := <-failed:
		t.Fatalf("reader failed during migration: %s", msg)
	default:
	}
}
