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
	"testing"
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
