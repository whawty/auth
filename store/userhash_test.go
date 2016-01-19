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

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const (
	testBaseDir string = "test-store"
)

func TestAddRemoveUser(t *testing.T) {
	username := "test-addremove-user"
	password := "secret"

	s, _ := NewDir(testBaseDir)
	u := NewUserHash(s, username)

	if err := u.Add(password, false); err != nil {
		t.Fatal("unexpected error:", err)
	}
	if _, err := os.Stat(filepath.Join(testBaseDir, username+".user")); err != nil {
		t.Fatal("cannot read test user file after add:", err)
	}

	if err := u.Add(password, false); err == nil {
		t.Fatal("adding user a second time returned no error!")
	}

	u.Remove()
	if _, err := os.Stat(filepath.Join(testBaseDir, username+".user")); err == nil {
		t.Fatal("test user does still exist after remove")
	} else if !os.IsNotExist(err) {
		t.Fatal("unexpected error:", err)
	}
}

func TestAddRemoveAdmin(t *testing.T) {
	username := "test-addremove-admin"
	password := "secret"

	s, _ := NewDir(testBaseDir)
	u := NewUserHash(s, username)

	if err := u.Add(password, true); err != nil {
		t.Fatal("unexpected error:", err)
	}
	if _, err := os.Stat(filepath.Join(testBaseDir, username+".admin")); err != nil {
		t.Fatal("cannot read test user file after add:", err)
	}

	if err := u.Add(password, true); err == nil {
		t.Fatal("adding user a second time returned no error!")
	}

	u.Remove()
	if _, err := os.Stat(filepath.Join(testBaseDir, username+".admin")); err == nil {
		t.Fatal("test user does still exist after remove")
	} else if !os.IsNotExist(err) {
		t.Fatal("unexpected error:", err)
	}
}

func TestAddUserAdmin(t *testing.T) {
	username := "test-add-user-admin"
	password := "secret"

	s, _ := NewDir(testBaseDir)
	u := NewUserHash(s, username)

	if err := u.Add(password, false); err != nil {
		t.Fatal("unexpected error:", err)
	}
	defer u.Remove()

	if err := u.Add(password, true); err == nil {
		t.Fatal("re-adding existing user as admin shouldn't work")
	}
}

func TestAddAdminUser(t *testing.T) {
	username := "test-add-user-admin"
	password := "secret"

	s, _ := NewDir(testBaseDir)
	u := NewUserHash(s, username)

	if err := u.Add(password, true); err != nil {
		t.Fatal("unexpected error:", err)
	}
	defer u.Remove()

	if err := u.Add(password, false); err == nil {
		t.Fatal("re-adding existing user as normal user shouldn't work")
	}
}

func TestExistsUser(t *testing.T) {
	username := "test-exists-user"
	password := "secret"

	s, _ := NewDir(testBaseDir)
	u := NewUserHash(s, username)

	if exists, _, err := u.Exists(); err != nil {
		t.Fatal("unexpected error:", err)
	} else if exists {
		t.Fatal("hash file for test user shouldn't exist")
	}

	if err := u.Add(password, false); err != nil {
		t.Fatal("unexpected error:", err)
	}
	defer u.Remove()

	if exists, isAdmin, err := u.Exists(); err != nil {
		t.Fatal("unexpected error:", err)
	} else if !exists {
		t.Fatal("hash file for test user should exist")
	} else if isAdmin {
		t.Fatal("test user shouldn't be an admin")
	}
}

func TestExistsAdmin(t *testing.T) {
	username := "test-exists-admin"
	password := "secret"

	s, _ := NewDir(testBaseDir)
	u := NewUserHash(s, username)

	if err := u.Add(password, true); err != nil {
		t.Fatal("unexpected error:", err)
	}
	defer u.Remove()

	if exists, isAdmin, err := u.Exists(); err != nil {
		t.Fatal("unexpected error:", err)
	} else if !exists {
		t.Fatal("test user should exist")
	} else if !isAdmin {
		t.Fatal("test user should be an admin")
	}
}

func TestAuthenticate(t *testing.T) {
	username := "test-auth"
	password1 := "secret1"
	password2 := "secret2"

	s, _ := NewDir(testBaseDir)
	u := NewUserHash(s, username)

	if err := u.Add(password1, true); err != nil {
		t.Fatal("unexpected error:", err)
	}
	defer u.Remove()

	if isAuthOk, isAdmin, _ := u.Authenticate(password1); !isAuthOk {
		t.Fatal("authentication should succeed")
	} else if !isAdmin {
		t.Fatal("test user should be an admin")
	}

	if isAuthOk, isAdmin, _ := u.Authenticate(password2); isAuthOk {
		t.Fatal("authentication shouldn't succeed")
	} else if !isAdmin {
		t.Fatal("test user should be an admin")
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
