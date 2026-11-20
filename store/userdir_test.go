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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestDir returns a store with cheap argon2id parameter-sets 1 (default) and 2 but no users.
func newTestDir(t *testing.T) *Dir {
	t.Helper()
	d := NewDir(t.TempDir())
	for id, mem := range map[uint]uint32{1: 1024, 2: 2048} {
		h, err := NewArgon2IDHasher(&Argon2IDParams{Time: 1, Memory: mem, Threads: 1, Length: 16})
		if err != nil {
			t.Fatal(err)
		}
		d.Params[id] = h
	}
	d.Default = 1
	return d
}

func testHashLine(t *testing.T, d *Dir, password string) string {
	t.Helper()
	line, err := NewUserHash(d, "x").generateHashLine(password, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return line
}

// putV2User stores user in format v2 by building its directory in .tmp and renaming it
// into place, like writers do.
func putV2User(t *testing.T, d *Dir, user, password string, isAdmin bool, extra map[string]string) {
	t.Helper()
	putV2Line(t, d, user, testHashLine(t, d, password), isAdmin, extra)
}

func putV2Line(t *testing.T, d *Dir, user, line string, isAdmin bool, extra map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(d.BaseDir, tmpDir), 0700); err != nil {
		t.Fatal(err)
	}
	tmp, err := os.MkdirTemp(filepath.Join(d.BaseDir, tmpDir), "test-")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{hashFile: line}
	if isAdmin {
		files[adminFile] = ""
	}
	for name, content := range extra {
		files[name] = content
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(tmp, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(tmp, filepath.Join(d.BaseDir, user)); err != nil {
		t.Fatal(err)
	}
}

// putV1User stores user as a v1 file.
func putV1User(t *testing.T, d *Dir, user, password string, isAdmin bool) {
	t.Helper()
	putV1Line(t, d, user, testHashLine(t, d, password), isAdmin)
}

// putV1Line stores user as a v1 file, written to .tmp first and renamed into place.
func putV1Line(t *testing.T, d *Dir, user, line string, isAdmin bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(d.BaseDir, tmpDir), 0700); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(d.BaseDir, tmpDir, "v1-"+user)
	if err := os.WriteFile(tmp, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, NewUserHash(d, user).getFilename(isAdmin)); err != nil {
		t.Fatal(err)
	}
}

func TestV2Read(t *testing.T) {
	d := newTestDir(t)
	putV2User(t, d, "root", "rootpw", true, nil)
	putV2User(t, d, "alice", "pw", false, map[string]string{"totp": "{}", ".hidden": "x"})

	if ok, isAdmin, _, _, err := d.Authenticate("root", "rootpw"); !ok || !isAdmin || err != nil {
		t.Fatalf("authenticate root: ok=%v admin=%v err=%v", ok, isAdmin, err)
	}
	if ok, isAdmin, _, _, err := d.Authenticate("alice", "pw"); !ok || isAdmin || err != nil {
		t.Fatalf("authenticate alice: ok=%v admin=%v err=%v", ok, isAdmin, err)
	}
	if ok, _, _, _, _ := d.Authenticate("alice", "wrong"); ok {
		t.Fatal("wrong password accepted")
	}
	if exists, isAdmin, err := d.Exists("root"); !exists || !isAdmin || err != nil {
		t.Fatalf("exists root: %v %v %v", exists, isAdmin, err)
	}
	if exists, _, err := d.Exists("bob"); exists || err != nil {
		t.Fatalf("exists bob: %v %v", exists, err)
	}
	if err := d.Check(); err != nil {
		t.Fatalf("Check(): %v", err)
	}
	list, err := d.ListFull()
	if err != nil || len(list) != 2 || !list["root"].IsAdmin || list["alice"].IsAdmin || !list["alice"].IsSupported {
		t.Fatalf("ListFull(): %v, %+v", err, list)
	}
	if l, err := d.List(); err != nil || len(l) != 2 {
		t.Fatalf("List(): %v, %+v", err, l)
	}
}

// Check() still requires an admin.
func TestV2CheckNeedsAdmin(t *testing.T) {
	d := newTestDir(t)
	putV2User(t, d, "alice", "pw", false, nil)
	if err := d.Check(); err != errNoSupportedHash {
		t.Fatalf("Check() without admin returned: %v", err)
	}
}

// rsync creates the directory of a new user before its files arrive.
func TestV2DirWithoutHash(t *testing.T) {
	d := newTestDir(t)
	putV2User(t, d, "root", "rootpw", true, nil)
	if err := os.MkdirAll(filepath.Join(d.BaseDir, "alice", ".~tmp~"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.BaseDir, "alice", adminFile), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if exists, _, err := d.Exists("alice"); exists || err != nil {
		t.Fatalf("user without hash file exists: %v, %v", exists, err)
	}
	if ok, _, _, _, err := d.Authenticate("alice", "pw"); ok || err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("authenticate user without hash file: %v, %v", ok, err)
	}
	if err := d.Check(); err != nil {
		t.Fatalf("Check(): %v", err)
	}
	if list, err := d.ListFull(); err != nil || len(list) != 1 {
		t.Fatalf("ListFull(): %v, %+v", err, list)
	}
}

// While a store gets migrated a user may exist in both formats, v2 wins.
func TestV2TakesPrecedence(t *testing.T) {
	d := newTestDir(t)
	putV1User(t, d, "root", "oldroot", true)
	putV2User(t, d, "root", "newroot", false, nil)
	putV1User(t, d, "admin", "adminpw", true)

	if ok, isAdmin, _, _, _ := d.Authenticate("root", "newroot"); !ok || isAdmin {
		t.Fatalf("v2 user not used: ok=%v admin=%v", ok, isAdmin)
	}
	if ok, _, _, _, _ := d.Authenticate("root", "oldroot"); ok {
		t.Fatal("password of the v1 file accepted")
	}
	if err := d.Check(); err != nil {
		t.Fatalf("Check(): %v", err)
	}
	list, err := d.ListFull()
	if err != nil || len(list) != 2 || list["root"].IsAdmin || !list["admin"].IsAdmin {
		t.Fatalf("ListFull(): %v, %+v", err, list)
	}
}

// A user named like the v1 file of another user, as user names may contain dots.
func TestV2LookupThroughV1File(t *testing.T) {
	d := newTestDir(t)
	putV1User(t, d, "alice", "pw", true)
	if exists, _, err := d.Exists("alice.admin"); exists || err != nil {
		t.Fatalf("exists alice.admin: %v, %v", exists, err)
	}
	if ok, _, _, _, err := d.Authenticate("alice.admin", "pw"); ok || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("authenticate alice.admin: %v, %v", ok, err)
	}
	mustAuthenticate(t, d, "alice", "pw")
}

// toggleFormat keeps moving user between format v1 and v2, always creating the new copy
// before removing the old one, like the migration does.
func toggleFormat(t *testing.T, d *Dir, user, password string) (stop func() int) {
	t.Helper()
	done := make(chan struct{})
	moves := make(chan int)
	u := NewUserHash(d, user)
	line := testHashLine(t, d, password)
	go func() {
		for i := 0; ; i++ {
			select {
			case <-done:
				moves <- i
				return
			default:
			}
			if i%2 == 0 {
				putV2Line(t, d, user, line, false, nil)
				if err := os.Remove(u.getFilename(false)); err != nil {
					t.Error(err)
				}
			} else {
				putV1Line(t, d, user, line, false)
				if err := os.RemoveAll(u.getDir()); err != nil {
					t.Error(err)
				}
			}
		}
	}()
	return func() int {
		close(done)
		return <-moves
	}
}

func TestReadersDuringFormatChange(t *testing.T) {
	d := newTestDir(t)
	putV2User(t, d, "root", "rootpw", true, nil)
	putV1User(t, d, "alice", "pw", false)

	stop := toggleFormat(t, d, "alice", "pw")
	const n = 2000
	failed := 0
	for i := 0; i < n; i++ {
		if ok, _, _, _, err := d.Authenticate("alice", "pw"); !ok || err != nil {
			failed++
			if failed == 1 {
				t.Errorf("authenticate failed: %v", err)
			}
		}
		if i%20 == 0 {
			if err := d.Check(); err != nil {
				t.Errorf("Check(): %v", err)
			}
			if list, err := d.ListFull(); err != nil || !list["root"].IsAdmin {
				t.Errorf("ListFull(): %v, %+v", err, list)
			}
		}
	}
	moves := stop()
	if failed > 0 {
		t.Fatalf("correct password rejected %d of %d times (%d format changes meanwhile)", failed, n, moves)
	}
}

func TestV2Writers(t *testing.T) {
	d := newTestDir(t)
	if err := d.Init("root", "rootpw"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{hashFile, adminFile} {
		if _, err := os.Stat(filepath.Join(d.BaseDir, "root", name)); err != nil {
			t.Fatalf("Init() didn't create '%s': %v", name, err)
		}
	}
	mustAdd(t, d, "alice", "pw1", false)
	aliceDir := filepath.Join(d.BaseDir, "alice")
	totp := filepath.Join(aliceDir, "totp")
	if err := os.WriteFile(totp, []byte("{\"secret\":1}"), 0600); err != nil {
		t.Fatal(err)
	}
	checkTotp := func(op string) {
		t.Helper()
		if data, err := os.ReadFile(totp); err != nil || string(data) != "{\"secret\":1}" {
			t.Fatalf("%s changed the extension file: %q, %v", op, data, err)
		}
	}

	if err := d.UpdateUser("alice", "pw2"); err != nil {
		t.Fatal(err)
	}
	checkTotp("update")
	mustAuthenticate(t, d, "alice", "pw2")

	if err := d.SetAdmin("alice", true); err != nil {
		t.Fatal(err)
	}
	checkTotp("set-admin")
	if _, isAdmin, _ := d.Exists("alice"); !isAdmin {
		t.Fatal("alice is no admin after set-admin")
	}
	if err := d.SetAdmin("alice", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(aliceDir, adminFile)); !os.IsNotExist(err) {
		t.Fatalf("admin file still exists: %v", err)
	}

	_, before, _, _, err := readHashStr(filepath.Join(aliceDir, hashFile))
	if err != nil {
		t.Fatal(err)
	}
	d.Default = 2
	if upgraded, err := d.UpgradeUser("alice", "pw2"); err != nil || !upgraded {
		t.Fatalf("upgrade: %v, %v", upgraded, err)
	}
	checkTotp("upgrade")
	if _, after, paramID, _, _ := readHashStr(filepath.Join(aliceDir, hashFile)); paramID != 2 || !after.Equal(before) {
		t.Fatalf("upgrade wrote parameter-set %d and last-change %v, expected 2 and %v", paramID, after, before)
	}
	mustAuthenticate(t, d, "alice", "pw2")

	if err := d.Check(); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveUser("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(aliceDir); !os.IsNotExist(err) {
		t.Fatalf("user directory still exists: %v", err)
	}
	if entries, err := os.ReadDir(filepath.Join(d.BaseDir, tmpDir)); err != nil || len(entries) != 1 || entries[0].Name() != lockFile {
		t.Fatalf("writers left things behind in .tmp: %v, %v", entries, err)
	}
}

// Until a store has been migrated, writers keep using format v1, also for new users.
func TestV1StoreStaysV1(t *testing.T) {
	d := newHardeningTestDir(t)
	mustAdd(t, d, "bob", "pw", true)
	if _, err := os.Stat(filepath.Join(d.BaseDir, "bob.admin")); err != nil {
		t.Fatalf("new user in a v1 store is not a v1 file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(d.BaseDir, "bob")); !os.IsNotExist(err) {
		t.Fatalf("new user in a v1 store got a directory: %v", err)
	}
}

// User names may contain dots: 'alice.user' must never touch the v1 file of user 'alice'.
func TestV2RemoveSparesV1FileOfOtherUser(t *testing.T) {
	d := newHardeningTestDir(t)
	mustAdd(t, d, "alice", "pw", false)
	if err := d.RemoveUser("alice.user"); err != nil {
		t.Fatal(err)
	}
	mustAuthenticate(t, d, "alice", "pw")
}

// A directory without hash file is not a user, but adding one must not replace it.
func TestV2AddRefusesExistingDir(t *testing.T) {
	d := newTestDir(t)
	putV2User(t, d, "root", "rootpw", true, nil)
	for _, junk := range []bool{false, true} {
		if err := os.Mkdir(filepath.Join(d.BaseDir, "bob"), 0700); err != nil {
			t.Fatal(err)
		}
		if junk {
			if err := os.WriteFile(filepath.Join(d.BaseDir, "bob", "totp"), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := d.AddUser("bob", "pw", false); err == nil {
			t.Fatalf("adding a user over an existing directory succeeded (junk=%v)", junk)
		}
		if err := os.RemoveAll(filepath.Join(d.BaseDir, "bob")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestV2ReadersDuringWrites(t *testing.T) {
	d := newTestDir(t)
	if err := d.Init("root", "rootpw"); err != nil {
		t.Fatal(err)
	}
	mustAdd(t, d, "alice", "pw", false)

	stop := toggleAdmin(t, d, "alice")
	for i := 0; i < 1000; i++ {
		if ok, _, _, _, err := d.Authenticate("alice", "pw"); !ok || err != nil {
			t.Fatalf("authenticate failed during set-admin: %v", err)
		}
		if i%20 == 0 {
			if err := d.UpdateUser("alice", "pw"); err != nil {
				t.Fatal(err)
			}
			if err := d.Check(); err != nil {
				t.Fatalf("Check(): %v", err)
			}
		}
	}
	stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			if err := d.RemoveUser("alice"); err != nil {
				t.Error(err)
				return
			}
			if err := d.AddUser("alice", "pw", i%2 == 0); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
		}
		if _, _, _, _, err := d.Authenticate("alice", "pw"); err != nil && !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("authenticating a user being removed failed with: %v", err)
		}
	}
}
