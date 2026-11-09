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
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// newHardeningTestDir returns an initialized store in a temporary directory using
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
	if err := d.Init("root", "secret"); err != nil {
		t.Fatal(err)
	}
	return d
}

func mustAdd(t *testing.T, d *Dir, user, password string, isAdmin bool) {
	t.Helper()
	if err := d.AddUser(user, password, isAdmin); err != nil {
		t.Fatalf("adding user '%s' failed: %v", user, err)
	}
}

func mustAuthenticate(t *testing.T, d *Dir, user, password string) {
	t.Helper()
	if ok, _, _, _, err := d.Authenticate(user, password); !ok || err != nil {
		t.Fatalf("authenticating '%s' failed: %v", user, err)
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
