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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	lib "github.com/whawty/auth/store"
)

func writeTestStoreConfig(t *testing.T, cfg, baseDir string, defaultParamID int) {
	t.Helper()
	data := fmt.Sprintf(`basedir: %q
default: %d
params:
  - id: 1
    argon2id: {time: 1, memory: 1024, threads: 1, length: 16}
  - id: 2
    argon2id: {time: 1, memory: 2048, threads: 1, length: 16}
`, baseDir, defaultParamID)
	if err := os.WriteFile(cfg, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

// Many concurrent logins of upgradeable users must neither deadlock the store
// nor prevent the upgrades from happening.
func TestLocalUpgradesDontDeadlock(t *testing.T) {
	const numUsers = 200
	base := t.TempDir()
	storeDir := filepath.Join(base, "store")
	if err := os.Mkdir(storeDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "store.yml")

	writeTestStoreConfig(t, cfg, storeDir, 1)
	d, err := lib.NewDirFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Init("root", "pw"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < numUsers; i++ {
		if err := d.AddUser(fmt.Sprintf("u%d", i), "pw", false); err != nil {
			t.Fatal(err)
		}
	}

	// rotate the default parameter-set: every user is now upgradeable
	writeTestStoreConfig(t, cfg, storeDir, 2)
	s, err := NewStore(cfg, "local", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	st := s.GetInterface()

	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < numUsers; i++ {
			wg.Add(1)
			go func(user string) {
				defer wg.Done()
				if ok, _, _, err := st.Authenticate(user, "pw"); !ok || err != nil {
					t.Errorf("authenticating '%s' failed: %v", user, err)
				}
			}(fmt.Sprintf("u%d", i))
		}
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("store deadlocked")
	}

	// upgrades are best-effort, but at least some of them must have happened
	deadline := time.Now().Add(10 * time.Second)
	for {
		list, err := st.ListFull()
		if err != nil {
			t.Fatal(err)
		}
		upgraded := 0
		for _, u := range list {
			if u.ParamID == 2 {
				upgraded++
			}
		}
		if upgraded > 0 {
			t.Logf("%d of %d users upgraded", upgraded, numUsers)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no user has been upgraded")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for the upgrade queue to drain. The dispatcher handles one request at a
	// time, so once the queue is empty a round-trip through it ensures that no
	// upgrade is still writing to the store when the test directory gets removed.
	for len(s.localUpgradeChan) > 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := st.List(); err != nil {
		t.Fatal(err)
	}
}

// The app serializes the migration with all other requests and reports the migrated users.
func TestMigrate(t *testing.T) {
	base := t.TempDir()
	storeDir := filepath.Join(base, "store")
	if err := os.Mkdir(storeDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "store.yml")
	writeTestStoreConfig(t, cfg, storeDir, 1)
	d, err := lib.NewDirFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Init("root", "pw"); err != nil {
		t.Fatal(err)
	}
	// turn root into a user stored in format v1
	if err := os.Rename(filepath.Join(storeDir, "root", "hash"), filepath.Join(storeDir, "root.admin")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(storeDir, "root")); err != nil {
		t.Fatal(err)
	}

	s, err := NewStore(cfg, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	st := s.GetInterface()
	if migrated, err := st.Migrate(); err != nil || len(migrated) != 1 || migrated[0] != "root" {
		t.Fatalf("migrate: %v, %v", migrated, err)
	}
	if ok, isAdmin, _, err := st.Authenticate("root", "pw"); !ok || !isAdmin || err != nil {
		t.Fatalf("authenticate after migration: %v, %v, %v", ok, isAdmin, err)
	}
	if migrated, err := st.Migrate(); err != nil || len(migrated) != 0 {
		t.Fatalf("second migration: %v, %v", migrated, err)
	}
}
