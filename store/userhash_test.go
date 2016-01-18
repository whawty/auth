//
// Copyright (c) 2016 Christian Pointner <equinox@spreadspace.org>
//               2016 Markus Grüneis <gimpf@gimpf.org>
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

package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const (
	testBaseDir string = "test-store"
)

func TestAddRemoveAdmin(t *testing.T) {
	s, _ := NewStore(testBaseDir)
	u := NewUserHash(s, "test")

	if err := u.Add("secret", true); err != nil {
		t.Fatal("unexpected error:", err)
	}
	if _, err := os.Open(filepath.Join(testBaseDir, "test.admin")); err != nil {
		t.Fatal("cannot open test user file after add:", err)
	}

	if err := u.Add("secret", true); err == nil {
		t.Fatal("adding user a second time returned no error!")
	}

	u.Remove()
	if _, err := os.Open(filepath.Join(testBaseDir, "test.admin")); err == nil {
		t.Fatal("test user does still exist after remove")
	} else if !os.IsNotExist(err) {
		t.Fatal("unexpected error:", err)
	}
}

func TestAddRemoveUser(t *testing.T) {
	s, _ := NewStore(testBaseDir)
	u := NewUserHash(s, "test2")

	if err := u.Add("secret", false); err != nil {
		t.Fatal("unexpected error:", err)
	}
	if _, err := os.Open(filepath.Join(testBaseDir, "test2.user")); err != nil {
		t.Fatal("cannot open test user file after add:", err)
	}

	u.Remove()
	if _, err := os.Open(filepath.Join(testBaseDir, "test2.user")); err == nil {
		t.Fatal("test user does still exist after remove")
	} else if !os.IsNotExist(err) {
		t.Fatal("unexpected error:", err)
	}
}

func TestMain(m *testing.M) {
	if err := os.Mkdir(testBaseDir, 0755); err != nil {
		fmt.Println("Error creating store base directory:", err)
		os.Exit(-1)
	}

	ret := m.Run()

	if err := os.RemoveAll(testBaseDir); err != nil {
		fmt.Println("Error removing store base directory:", err)
	}
	os.Exit(ret)
}
