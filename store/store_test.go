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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/spreadspace/scryptauth.v2"
)

const (
	testBaseDirUserHash string = "test-store-user"
	testBaseDir         string = "test-store"
)

var (
	testStoreUserHash *Dir
)

func TestNewDirFromConfig(t *testing.T) {
	jsonData := []struct {
		s     string
		valid bool
	}{
		{"", false},
		{"{}", false},
		{`{ "basedir": "/tmp" }`, true},
		{`{ "basedir": "/tmp", "scryptauth": { "defaultctx": 0 } }`, true},
		{`{ "basedir": "/tmp", "scryptauth": { "defaultctx": 17 } }`, false},
		{`{ "basedir": "/tmp", "scryptauth": { "defaultctx": 17, "contexts": [
         { "ID": 0, "hmackey": "iVFvz2PW5g1Tge9mLttgRxBuu0OBXgD7uAOHySqi4QI=", "pwcost": 12 }
     ] } }`, false},
		{`{ "basedir": "/tmp", "scryptauth": { "defaultctx": 17, "contexts": [
         { "ID": 13, "hmackey": "iVFvz2PW5g1Tge9mLttgRxBuu0OBXgD7uAOHySqi4QI=", "pwcost": 12 }
     ] } }`, false},
		{`{ "basedir": "/tmp", "scryptauth": { "defaultctx": 17, "contexts": [
         { "ID": 17, "hmackey": "", "pwcost": 12 }
     ] } }`, false},
		{`{ "basedir": "/tmp", "scryptauth": { "defaultctx": 17, "contexts": [
         { "ID": 17, "hmackey": "e70t9ZiCR75KE4VoUHQM6wH05KORAfLV74bREA==", "pwcost": 12 }
     ] } }`, false},
		{`{ "basedir": "/tmp", "scryptauth": { "defaultctx": 17, "contexts": [
         { "ID": 17, "hmackey": "$$invalid§§", "pwcost": 12 }
     ] } }`, false},
		{`{ "basedir": "/tmp", "scryptauth": { "defaultctx": 17, "contexts": [
         { "ID": 17, "hmackey": "iVFvz2PW5g1Tge9mLttgRxBuu0OBXgD7uAOHySqi4QI=", "pwcost": 33 }
     ] } }`, false},
		{`{ "basedir": "/tmp", "scryptauth": { "defaultctx": 0, "contexts": [
         { "ID": 17, "hmackey": "iVFvz2PW5g1Tge9mLttgRxBuu0OBXgD7uAOHySqi4QI=", "pwcost": 14 }
     ] } }`, false},
		{`{ "basedir": "/tmp", "scryptauth": { "defaultctx": 17, "contexts": [
         { "ID": 17, "hmackey": "iVFvz2PW5g1Tge9mLttgRxBuu0OBXgD7uAOHySqi4QI=", "pwcost": 12 }
     ] } }`, true},
		{`{ "basedir": "/tmp", "scryptauth": { "defaultctx": 17, "contexts": [
         { "ID": 17, "hmackey": "iVFvz2PW5g1Tge9mLttgRxBuu0OBXgD7uAOHySqi4QI=", "pwcost": 12 },
         { "ID": 18, "hmackey": "iVFvz2PW5g1Tge9mLttgRxBuu0OBXgD7uAOHySqi4QI=", "pwcost": 14, "p": 7, "r": 2 }
     ] } }`, true},
	}

	file, err := ioutil.TempFile("", "whawty-auth-config")
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	defer file.Close()
	defer os.Remove(file.Name())

	for _, json := range jsonData {
		if _, err := file.Seek(0, 0); err != nil {
			t.Fatal("unexpected error:", err)
		}
		if err := file.Truncate(0); err != nil {
			t.Fatal("unexpected error:", err)
		}
		if _, err := file.WriteString(json.s); err != nil {
			t.Fatal("unexpected error:", err)
		}

		if json.valid {
			if _, err := NewDirFromConfig(file.Name()); err != nil {
				t.Fatalf("NewDirFromConfig returned an unexpected error for '%s': %s", json.s, err)
			}
		} else {
			if _, err := NewDirFromConfig(file.Name()); err == nil {
				t.Fatalf("NewDirFromConfig didn't return with an error for '%s'", json.s)
			}
		}
	}
}

func TestInitDir(t *testing.T) {
	adminuser := "root"
	password := "verysecret"

	store := NewDir(testBaseDir)

	if err := store.Init(adminuser, password); err == nil {
		t.Fatalf("Initializing a not existing dir should give an error")
	}

	if file, err := os.Create(testBaseDir); err != nil {
		t.Fatal("unexpected error:", err)
	} else {
		file.Close()
	}

	if err := store.Init(adminuser, password); err == nil {
		t.Fatalf("Initializing where path is a not a dir should give an error")
	}

	if err := os.Remove(testBaseDir); err != nil {
		t.Fatal("unexpected error:", err)
	}
	if err := os.Mkdir(testBaseDir, 0000); err != nil {
		t.Fatal("unexpected error:", err)
	}
	defer os.RemoveAll(testBaseDir)

	if err := store.Init(adminuser, password); err == nil {
		t.Fatalf("Initializing of a directory with wrong permissions shouldn't work")
	}

	if err := os.Chmod(testBaseDir, 0755); err != nil {
		t.Fatal("unexpected error:", err)
	}
	if file, err := os.Create(filepath.Join(testBaseDir, "testfile")); err != nil {
		t.Fatal("unexpected error:", err)
	} else {
		file.Close()
	}

	if err := store.Init(adminuser, password); err == nil {
		t.Fatalf("Initializing a non-empty directory should give an error")
	}

	if err := os.Remove(filepath.Join(testBaseDir, "testfile")); err != nil {
		t.Fatal("unexpected error:", err)
	}

	if err := store.Init(adminuser, password); err == nil {
		t.Fatalf("Initializing a directory without a context should give an error")
	}

	store.Scryptauth.DefaultCtxID = 1
	ctx, _ := scryptauth.New(14, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	store.Scryptauth.Contexts[store.Scryptauth.DefaultCtxID] = ctx

	if err := store.Init(adminuser, password); err != nil {
		t.Fatalf("unexpected error")
	}
}

func TestCheckDir(t *testing.T) {
	store := NewDir(testBaseDir)

	if ok, err := store.Check(); err == nil && ok == true {
		t.Fatalf("check should return an error for not existing directory")
	}

	if file, err := os.Create(testBaseDir); err != nil {
		t.Fatal("unexpected error:", err)
	} else {
		file.Close()
	}

	if ok, err := store.Check(); err == nil && ok == true {
		t.Fatalf("check should return an error if path is not a directory")
	}

	if err := os.Remove(testBaseDir); err != nil {
		t.Fatal("unexpected error:", err)
	}
	if err := os.Mkdir(testBaseDir, 0000); err != nil {
		t.Fatal("unexpected error:", err)
	}
	defer os.RemoveAll(testBaseDir)

	if ok, err := store.Check(); err == nil && ok == true {
		t.Fatalf("check should return an error if directory is not accessable")
	}

	if err := os.Chmod(testBaseDir, 0755); err != nil {
		t.Fatal("unexpected error:", err)
	}

	if ok, err := store.Check(); err == nil && ok == true {
		t.Fatalf("check should return an error for an empty directory")
	}
	// TODO: add more tests
}

func TestList(t *testing.T) {
	adminuser := "root"
	password := "verysecret"
	user1 := "test"
	password1 := "secret"

	store := NewDir(testBaseDir)

	if err := os.Mkdir(testBaseDir, 0755); err != nil {
		t.Fatal("unexpected error:", err)
	}
	defer os.RemoveAll(testBaseDir)

	if list, err := store.List(); err != nil {
		t.Fatalf("unexpected error")
	} else if len(list) != 0 {
		t.Fatalf("list should return an empty user list for an empty directory")
	}

	store.Scryptauth.DefaultCtxID = 1
	ctx, _ := scryptauth.New(14, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	store.Scryptauth.Contexts[store.Scryptauth.DefaultCtxID] = ctx

	if err := store.Init(adminuser, password); err != nil {
		t.Fatalf("unexpected error")
	}

	if list, err := store.List(); err != nil {
		t.Fatalf("unexpected error")
	} else if len(list) != 1 {
		t.Fatalf("list should return a list of length 1")
	} else {
		if user, ok := list[adminuser]; !ok || !user.IsAdmin {
			t.Fatalf("list returned wrong user list")
		}
	}

	if err := store.AddUser(user1, password1, false); err != nil {
		t.Fatalf("unexpected error")
	}

	if list, err := store.List(); err != nil {
		t.Fatalf("unexpected error")
	} else if len(list) != 2 {
		t.Fatalf("list should return a list of length 2")
	} else {
		if user, ok := list[adminuser]; !ok || !user.IsAdmin {
			t.Fatalf("list returned wrong user list")
		}
		if user, ok := list[user1]; !ok || user.IsAdmin {
			t.Fatalf("list returned wrong user list")
		}
	}

	if err := store.SetAdmin(user1, true); err != nil {
		t.Fatalf("unexpected error")
	}

	if list, err := store.List(); err != nil {
		t.Fatalf("unexpected error")
	} else if len(list) != 2 {
		t.Fatalf("list should return a list of length 2")
	} else {
		if user, ok := list[adminuser]; !ok || !user.IsAdmin {
			t.Fatalf("list returned wrong user list")
		}
		if user, ok := list[user1]; !ok || !user.IsAdmin {
			t.Fatalf("list returned wrong user list")
		}
	}
}

func TestMain(m *testing.M) {
	if err := os.Mkdir(testBaseDirUserHash, 0755); err != nil {
		fmt.Println("Error creating store base directory:", err)
		os.Exit(-1)
	}

	testStoreUserHash = NewDir(testBaseDirUserHash)
	testStoreUserHash.Scryptauth.DefaultCtxID = 1
	ctx, _ := scryptauth.New(14, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	testStoreUserHash.Scryptauth.Contexts[testStoreUserHash.Scryptauth.DefaultCtxID] = ctx

	ret := m.Run()

	if err := os.RemoveAll(testBaseDirUserHash); err != nil {
		fmt.Println("Error removing store base directory:", err)
	}
	os.Exit(ret)
}
