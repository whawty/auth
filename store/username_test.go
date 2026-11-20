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
	"strings"
	"testing"
	"time"
)

func newNameTestDir(t *testing.T) (*Dir, Hasher) {
	t.Helper()
	d := NewDir(t.TempDir())
	h, err := NewArgon2IDHasher(&Argon2IDParams{Time: 1, Memory: 1024, Threads: 1, Length: 16})
	if err != nil {
		t.Fatal(err)
	}
	d.Params[1] = h
	d.Default = 1
	if err := d.Init("root", "secret"); err != nil {
		t.Fatal(err)
	}
	return d, h
}

// User names come from clients and become part of paths, so they must never reach outside the store.
func TestInvalidNames(t *testing.T) {
	d, _ := newNameTestDir(t)
	for _, name := range []string{"", ".", "..", ".tmp", "../x", "a/b", "a/../b", "/etc/passwd", "a\\b", "a\nb", "a\x00b", "-a"} {
		// an invalid name behaves exactly like an unknown user
		if ok, _, _, _, err := d.Authenticate(name, "secret"); ok || err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("Authenticate(%q): ok=%v err=%v", name, ok, err)
		}
		if exists, _, err := d.Exists(name); exists || err != nil {
			t.Errorf("Exists(%q): %v, %v", name, exists, err)
		}
		if err := d.UpdateUser(name, "pw"); err == nil {
			t.Errorf("UpdateUser(%q) succeeded", name)
		}
		if err := d.SetAdmin(name, true); err == nil {
			t.Errorf("SetAdmin(%q) succeeded", name)
		}
		if err := NewUserHash(d, name).Add("pw", true); err == nil {
			t.Errorf("Add(%q) succeeded", name)
		}
		if upgraded, err := d.UpgradeUser(name, "secret"); upgraded || err == nil {
			t.Errorf("UpgradeUser(%q): %v, %v", name, upgraded, err)
		}
		if err := d.RemoveUser(name); err == nil {
			t.Errorf("RemoveUser(%q) succeeded", name)
		}
	}
}

// A hash file outside of the store must not be usable to log in, nor be changed or removed.
func TestNoPathTraversal(t *testing.T) {
	d, h := newNameTestDir(t)
	outside := t.TempDir()
	hashStr, err := h.Generate("mallory")
	if err != nil {
		t.Fatal(err)
	}
	line := fmt.Sprintf("argon2id:%d:1:%s\n", time.Now().Unix(), hashStr)
	target := filepath.Join(outside, "x.admin")
	if err := os.WriteFile(target, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	name, err := filepath.Rel(d.BaseDir, filepath.Join(outside, "x"))
	if err != nil {
		t.Fatal(err)
	}

	if ok, _, _, _, _ := d.Authenticate(name, "mallory"); ok {
		t.Fatalf("logged in as %q using a hash file outside of the store", name)
	}
	if err := d.UpdateUser(name, "changed"); err == nil {
		t.Fatalf("UpdateUser(%q) succeeded", name)
	}
	if err := d.RemoveUser(name); err == nil {
		t.Fatalf("RemoveUser(%q) succeeded", name)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != line {
		t.Fatalf("file outside of the store has been changed or removed: %q, %v", data, err)
	}
}
