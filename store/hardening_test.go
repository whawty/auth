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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testAuxData = "totp: eyJ0ZXN0IjoidmFsdWUifQ\nwebauthn: eyJmb28iOiJiYXIifQ\n"

// newHardeningTestDir returns a store in format v1 in a temporary directory using
// cheap argon2id parameter-sets 1 (default) and 2.
func newHardeningTestDir(t *testing.T) *Dir {
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
	// These tests cover the v1 code paths, which are used until a store has been migrated.
	putV1User(t, d, "root", "secret", true)
	return d
}

func mustAdd(t *testing.T, d *Dir, user, password string, isAdmin bool) {
	t.Helper()
	if err := d.AddUser(user, password, isAdmin); err != nil {
		t.Fatalf("adding user '%s' failed: %v", user, err)
	}
}

func appendAuxData(t *testing.T, filename string) {
	t.Helper()
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(testAuxData); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func readAuxData(t *testing.T, filename string) string {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	_, aux, _ := strings.Cut(string(data), "\n")
	return aux
}

func mustAuthenticate(t *testing.T, d *Dir, user, password string) {
	t.Helper()
	if ok, _, _, _, err := d.Authenticate(user, password); !ok || err != nil {
		t.Fatalf("authenticating '%s' failed: %v", user, err)
	}
}

// #24: auxiliary data must survive every operation that rewrites the first line.
func TestAuxDataPreserved(t *testing.T) {
	d := newHardeningTestDir(t)
	mustAdd(t, d, "alice", "pw1", false)
	filename := filepath.Join(d.BaseDir, "alice.user")
	appendAuxData(t, filename)

	if err := d.UpdateUser("alice", "pw2"); err != nil {
		t.Fatal(err)
	}
	if aux := readAuxData(t, filename); aux != testAuxData {
		t.Fatalf("aux data changed by update: %q", aux)
	}

	if err := d.SetAdmin("alice", true); err != nil {
		t.Fatal(err)
	}
	filename = filepath.Join(d.BaseDir, "alice.admin")
	if aux := readAuxData(t, filename); aux != testAuxData {
		t.Fatalf("aux data changed by set-admin: %q", aux)
	}

	d.Default = 2
	if upgraded, err := d.UpgradeUser("alice", "pw2"); err != nil || !upgraded {
		t.Fatalf("upgrade failed: %v (upgraded=%v)", err, upgraded)
	}
	if aux := readAuxData(t, filename); aux != testAuxData {
		t.Fatalf("aux data changed by upgrade: %q", aux)
	}
	mustAuthenticate(t, d, "alice", "pw2")
}

// #24: auxiliary data must not influence how the hash is parsed.
func TestAuxDataIgnoredByParser(t *testing.T) {
	d := newHardeningTestDir(t)
	mustAdd(t, d, "plain", "pw", false)
	mustAdd(t, d, "withaux", "pw", true)
	appendAuxData(t, filepath.Join(d.BaseDir, "withaux.admin"))

	for _, name := range []string{"plain.user", "withaux.admin"} {
		filename := filepath.Join(d.BaseDir, name)
		formatID, _, paramID, hashStr, err := readHashStr(filename)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if formatID != "argon2id" || paramID != 1 || strings.ContainsAny(hashStr, "\n") {
			t.Fatalf("%s: parsed wrongly: %q %d %q", name, formatID, paramID, hashStr)
		}
		if err := isFormatSupported(filename, d); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	mustAuthenticate(t, d, "plain", "pw")
	mustAuthenticate(t, d, "withaux", "pw")

	list, err := d.ListFull()
	if err != nil {
		t.Fatal(err)
	}
	if !list["withaux"].IsSupported || !list["plain"].IsSupported {
		t.Fatalf("ListFull reports wrong support status: %+v", list)
	}
	if err := d.Check(); err != nil {
		t.Fatal(err)
	}
}

// A failed add must not leave an (empty) user file behind.
func TestAddUserFailureLeavesNoFile(t *testing.T) {
	d := newHardeningTestDir(t)
	tmp := filepath.Join(d.BaseDir, tmpDir)
	if err := os.RemoveAll(tmp); err != nil {
		t.Fatal(err)
	}
	// a regular file in place of the temp directory makes every write fail
	if err := os.WriteFile(tmp, nil, 0600); err != nil {
		t.Fatal(err)
	}

	if err := d.AddUser("alice", "pw", false); err == nil {
		t.Fatal("adding a user without writable temp directory succeeded")
	}
	if exists, _, _ := d.Exists("alice"); exists {
		t.Fatal("failed add left a user file behind")
	}
}

func TestAddUserNoOverwrite(t *testing.T) {
	d := newHardeningTestDir(t)
	mustAdd(t, d, "alice", "pw", false)
	if err := d.AddUser("alice", "other", true); err == nil {
		t.Fatal("adding an existing user succeeded")
	}
	mustAuthenticate(t, d, "alice", "pw")
}

// Hidden files, like the temporary files rsync creates, must be ignored.
func TestHiddenFilesIgnored(t *testing.T) {
	d := newHardeningTestDir(t)
	mustAdd(t, d, "alice", "pw", false)
	for _, name := range []string{".alice.user.a1B2c3", ".~tmp~", ".something"} {
		if err := os.WriteFile(filepath.Join(d.BaseDir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Check(); err != nil {
		t.Fatalf("Check() failed: %v", err)
	}
	if list, err := d.List(); err != nil || len(list) != 2 {
		t.Fatalf("List() failed: %v, %+v", err, list)
	}
	if list, err := d.ListFull(); err != nil || len(list) != 2 {
		t.Fatalf("ListFull() failed: %v, %+v", err, list)
	}
}

func TestRemoveUser(t *testing.T) {
	d := newHardeningTestDir(t)
	mustAdd(t, d, "alice", "pw", false)
	if err := d.RemoveUser("alice"); err != nil {
		t.Fatal(err)
	}
	if exists, _, _ := d.Exists("alice"); exists {
		t.Fatal("user still exists after remove")
	}
	if err := d.RemoveUser("alice"); err != nil {
		t.Fatalf("removing a non-existing user failed: %v", err)
	}
}

func TestUpgradeUser(t *testing.T) {
	d := newHardeningTestDir(t)
	mustAdd(t, d, "alice", "pw", false)

	if upgraded, err := d.UpgradeUser("alice", "pw"); err != nil || upgraded {
		t.Fatalf("upgrade with unchanged default: upgraded=%v, err=%v", upgraded, err)
	}

	d.Default = 2
	if upgraded, err := d.UpgradeUser("alice", "wrong"); err == nil || upgraded {
		t.Fatalf("upgrade with wrong password: upgraded=%v, err=%v", upgraded, err)
	}
	if upgraded, err := d.UpgradeUser("alice", "pw"); err != nil || !upgraded {
		t.Fatalf("upgrade failed: upgraded=%v, err=%v", upgraded, err)
	}
	if _, _, paramID, _, _ := readHashStr(filepath.Join(d.BaseDir, "alice.user")); paramID != 2 {
		t.Fatalf("upgrade wrote parameter-set %d", paramID)
	}
	mustAuthenticate(t, d, "alice", "pw")
}

// An upgrade doesn't change the password, so it must keep the time of the last change.
func TestUpgradeUserKeepsLastChange(t *testing.T) {
	d := newHardeningTestDir(t)
	mustAdd(t, d, "alice", "pw", false)
	filename := filepath.Join(d.BaseDir, "alice.user")

	// pretend the password has been set a year ago
	line, err := readHashLine(filename)
	if err != nil {
		t.Fatal(err)
	}
	formatID, _, paramID, hashStr, err := parseHashLine(line)
	if err != nil {
		t.Fatal(err)
	}
	then := time.Now().Add(-365 * 24 * time.Hour).Truncate(time.Second)
	line = fmt.Sprintf("%s:%d:%d:%s\n", formatID, then.Unix(), paramID, hashStr)
	if err := os.WriteFile(filename, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}

	d.Default = 2
	if upgraded, err := d.UpgradeUser("alice", "pw"); err != nil || !upgraded {
		t.Fatalf("upgrade failed: upgraded=%v, err=%v", upgraded, err)
	}
	_, lastChange, paramID, _, err := readHashStr(filename)
	if err != nil {
		t.Fatal(err)
	}
	if paramID != 2 || !lastChange.Equal(then) {
		t.Fatalf("upgrade wrote parameter-set %d and last-change %v, expected 2 and %v", paramID, lastChange, then)
	}

	if err := d.UpdateUser("alice", "new"); err != nil {
		t.Fatal(err)
	}
	if _, lastChange, _, _, _ = readHashStr(filename); !lastChange.After(then) {
		t.Fatalf("password change kept last-change %v", lastChange)
	}
}

// An upgrade queued with the old password must not revert a password change.
func TestUpgradeAfterPasswordChange(t *testing.T) {
	d := newHardeningTestDir(t)
	mustAdd(t, d, "alice", "old", false)
	d.Default = 2
	// alice logs in with "old", an upgrade gets queued, then she changes her password
	if err := d.UpdateUser("alice", "new"); err != nil {
		t.Fatal(err)
	}
	d.Default = 1
	if upgraded, _ := d.UpgradeUser("alice", "old"); upgraded {
		t.Fatal("upgrade with old password succeeded")
	}
	mustAuthenticate(t, d, "alice", "new")
	if ok, _, _, _, _ := d.Authenticate("alice", "old"); ok {
		t.Fatal("old password is valid again")
	}
}

func TestLockIsExclusive(t *testing.T) {
	d := newHardeningTestDir(t)
	unlock, err := d.lock()
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan struct{})
	go func() {
		unlock2, err := d.lock()
		if err != nil {
			t.Error(err)
			return
		}
		close(acquired)
		unlock2()
	}()
	select {
	case <-acquired:
		t.Fatal("second lock acquired while first one is held")
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	select {
	case <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("second lock not acquired after release")
	}
}

// Concurrent SetAdmin and Update must never leave both a .user and an .admin file.
func TestConcurrentSetAdminUpdate(t *testing.T) {
	d := newHardeningTestDir(t)
	mustAdd(t, d, "alice", "pw", false)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := d.SetAdmin("alice", i%2 == 0); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for i := 0; i < 200; i++ {
		if err := d.UpdateUser("alice", "pw"); err != nil {
			t.Error(err)
			break
		}
		// hold the store lock so SetAdmin can't rename the file between the two checks
		unlock, err := d.lock()
		if err != nil {
			t.Fatal(err)
		}
		_, eu := os.Stat(filepath.Join(d.BaseDir, "alice.user"))
		_, ea := os.Stat(filepath.Join(d.BaseDir, "alice.admin"))
		unlock()
		if eu == nil && ea == nil {
			t.Error("both alice.user and alice.admin exist")
			break
		}
	}
	close(stop)
	wg.Wait()
	if err := d.Check(); err != nil {
		t.Fatal(err)
	}
	mustAuthenticate(t, d, "alice", "pw")
}

// A second writer that takes the store lock must not lose data to concurrent updates.
func TestConcurrentAuxWriter(t *testing.T) {
	d := newHardeningTestDir(t)
	mustAdd(t, d, "alice", "pw", false)
	filename := filepath.Join(d.BaseDir, "alice.user")

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := d.UpdateUser("alice", "pw"); err != nil {
				t.Error(err)
				return
			}
		}
	}()

	const n = 300
	for i := 0; i < n; i++ {
		func() {
			unlock, err := d.lock()
			if err != nil {
				t.Fatal(err)
			}
			defer unlock()
			data, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			tmp, err := d.getTempFile()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tmp.Write(append(data, "x: 1\n"...)); err != nil {
				t.Fatal(err)
			}
			if err := tmp.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp.Name(), filename); err != nil {
				t.Fatal(err)
			}
		}()
	}
	close(stop)
	wg.Wait()

	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if lines := bytes.Count(data, []byte("x: 1\n")); lines != n {
		t.Fatalf("aux lines written: %d, surviving: %d", n, lines)
	}
}

// toggleAdmin keeps changing the admin status of user until the returned function is called.
func toggleAdmin(t *testing.T, d *Dir, user string) (stop func() int) {
	t.Helper()
	done := make(chan struct{})
	toggles := make(chan int)
	go func() {
		for i := 0; ; i++ {
			select {
			case <-done:
				toggles <- i
				return
			default:
			}
			if err := d.SetAdmin(user, i%2 == 0); err != nil {
				t.Error(err)
			}
		}
	}()
	return func() int {
		close(done)
		return <-toggles
	}
}

// Readers don't take the store lock, so they must find users while SetAdmin() renames their files.
func TestReadersDuringSetAdmin(t *testing.T) {
	d := newHardeningTestDir(t)
	mustAdd(t, d, "alice", "pw", false)

	stop := toggleAdmin(t, d, "alice")
	const n = 2000
	failed := 0
	for i := 0; i < n; i++ {
		if ok, _, _, _, err := d.Authenticate("alice", "pw"); !ok || err != nil {
			failed++
			if failed == 1 {
				t.Errorf("authenticate failed: %v", err)
			}
		}
		if exists, _, err := d.Exists("alice"); !exists || err != nil {
			t.Errorf("exists returned %v, %v", exists, err)
		}
		if i%20 == 0 {
			if err := d.Check(); err != nil {
				t.Errorf("Check(): %v", err)
			}
			list, err := d.ListFull()
			if err != nil {
				t.Errorf("ListFull(): %v", err)
			}
			for name, u := range list {
				if !u.IsSupported {
					t.Errorf("ListFull() reports '%s' as unsupported", name)
				}
			}
			if _, err := d.List(); err != nil {
				t.Errorf("List(): %v", err)
			}
		}
	}
	toggles := stop()
	if failed > 0 {
		t.Fatalf("correct password rejected %d of %d times (%d admin changes meanwhile)", failed, n, toggles)
	}
}

// A user removed while being authenticated must simply not exist.
func TestAuthenticateDuringRemove(t *testing.T) {
	d := newHardeningTestDir(t)
	mustAdd(t, d, "alice", "pw", false)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 300; i++ {
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
		_, _, _, _, err := d.Authenticate("alice", "pw")
		if err != nil && !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("authenticating a user being removed failed with: %v", err)
		}
	}
}

// A user really having both files must still make Check() fail.
func TestCheckDetectsDuplicate(t *testing.T) {
	d := newHardeningTestDir(t)
	mustAdd(t, d, "alice", "pw", false)
	data, err := os.ReadFile(filepath.Join(d.BaseDir, "alice.user"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.BaseDir, "alice.admin"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := d.Check(); err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("Check() on a user with both files returned: %v", err)
	}
}
