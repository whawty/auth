//
// Copyright (c) 2016 whawty contributors (see AUTHORS file)
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
	"crypto/rand"
	"fmt"
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

// TODO: replace this with generator for parameter-sets that can be used in the tests
func ensureDefaultParameterSet(store *Dir) error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}

	if store.Default == 0 {
		store.Default = 1
	}
	sactx, _ := scryptauth.New(14, b)
	store.Params[store.Default] = &ScryptAuthHasher{saCtx: sactx}
	return nil
}

func TestNewDirFromConfig(t *testing.T) {
	yamlData := []struct {
		s     string
		valid bool
	}{
		{"", false},            // empty file with no settings
		{`basedir: ""`, false}, // empty/no base dir
		{`basedir: "/tmp"`, true},
		{`basedir: "/tmp"
default: 0`, true},
		{`basedir: "/tmp"
default: 17`, false}, // default parameter-set is set to 17 but it does not exist
		{`basedir: "/tmp"
default: 1
params:
  - id: 1`, false}, // parameter-set has no valid algorithm
		{`basedir: "/tmp"
params:
  - id: 0
    scryptauth:
      hmackey: "iVFvz2PW5g1Tge9mLttgRxBuu0OBXgD7uAOHySqi4QI="
      cost: 12`, false}, // parameter-set 0 is invalid
		{`basedir: "/tmp"
default: 17
params:
  - id: 13
    scryptauth:
      hmackey: "iVFvz2PW5g1Tge9mLttgRxBuu0OBXgD7uAOHySqi4QI="
      cost: 12`, false}, // default parameter-set is set to 17 but does not exist
		{`basedir: "/tmp"
default: 17
params:
  - id: 17
    scryptauth:
      hmackey: ""
      cost: 12`, false}, // HMAC Key is empty
		{`basedir: "/tmp"
default: 17
params:
  - id: 17
    scryptauth:
      hmackey: "e70t9ZiCR75KE4VoUHQM6wH05KORAfLV74bREA=="
      cost: 12`, false}, // HMAC Key is too short
		{`basedir: "/tmp"
default: 17
params:
  - id: 17
    scryptauth:
      hmackey: "$$invalid§§"
      cost: 12`, false}, // invalid HMAC Key
		{`basedir: "/tmp"
default: 17
params:
  - id: 17
    scryptauth:
      hmackey: "iVFvz2PW5g1Tge9mLttgRxBuu0OBXgD7uAOHySqi4QI="
      cost: 33`, false}, // invalid PW-Cost parameter
		{`basedir: "/tmp"
default: 0
params:
  - id: 17
    scryptauth:
      hmackey: "iVFvz2PW5g1Tge9mLttgRxBuu0OBXgD7uAOHySqi4QI="
      cost: 14`, false}, // no default parameter-set but there is at least one parameter-set defined
		{`basedir: "/tmp"
default: 17
params:
  - id: 17
    scryptauth:
      hmackey: "iVFvz2PW5g1Tge9mLttgRxBuu0OBXgD7uAOHySqi4QI="
      cost: 12`, true},
		{`basedir: "/tmp"
default: 17
params:
  - id: 17
    scryptauth:
      hmackey: "iVFvz2PW5g1Tge9mLttgRxBuu0OBXgD7uAOHySqi4QI="
      cost: 12
  - id: 18
    scryptauth:
      hmackey: "iVFvz2PW5g1Tge9mLttgRxBuu0OBXgD7uAOHySqi4QI="
      cost: 14
      p: 7
      r: 2`, true},
	}

	file, err := os.CreateTemp("", "whawty-auth-config")
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	defer file.Close()           //nolint:errcheck
	defer os.Remove(file.Name()) //nolint:errcheck

	for _, yaml := range yamlData {
		if _, err := file.Seek(0, 0); err != nil {
			t.Fatal("unexpected error:", err)
		}
		if err := file.Truncate(0); err != nil {
			t.Fatal("unexpected error:", err)
		}
		if _, err := file.WriteString(yaml.s); err != nil {
			t.Fatal("unexpected error:", err)
		}

		if yaml.valid {
			if _, err := NewDirFromConfig(file.Name()); err != nil {
				t.Fatalf("NewDirFromConfig returned an unexpected error for '%s': %s", yaml.s, err)
			}
		} else {
			if _, err := NewDirFromConfig(file.Name()); err == nil {
				t.Fatalf("NewDirFromConfig didn't return with an error for '%s'", yaml.s)
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
		file.Close() //nolint:errcheck
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
	defer os.RemoveAll(testBaseDir) //nolint:errcheck

	if err := store.Init(adminuser, password); err == nil {
		t.Fatalf("Initializing of a directory with wrong permissions shouldn't work")
	}

	if err := os.Chmod(testBaseDir, 0755); err != nil {
		t.Fatal("unexpected error:", err)
	}
	if file, err := os.Create(filepath.Join(testBaseDir, "testfile")); err != nil {
		t.Fatal("unexpected error:", err)
	} else {
		file.Close() //nolint:errcheck
	}

	if err := store.Init(adminuser, password); err == nil {
		t.Fatalf("Initializing a non-empty directory should give an error")
	}

	if err := os.Remove(filepath.Join(testBaseDir, "testfile")); err != nil {
		t.Fatal("unexpected error:", err)
	}

	if err := store.Init(adminuser, password); err == nil {
		t.Fatalf("Initializing a directory without a parameter set should give an error")
	}

	if err := ensureDefaultParameterSet(store); err != nil {
		t.Fatal("Unexpected error:", err)
	}

	if err := store.Init(adminuser, password); err != nil {
		t.Fatal("unexpected error:", err)
	}

	if exists, err := fileExists(filepath.Join(testBaseDir, ".tmp")); err != nil || exists != true {
		t.Fatalf("A freshly-created base should contain .tmp")
	}
}

func TestCheckDir(t *testing.T) {
	store := NewDir(testBaseDir)

	if err := store.Check(); err == nil {
		t.Fatalf("check should return an error for non-existing directory")
	}

	if file, err := os.Create(testBaseDir); err != nil {
		t.Fatal("unexpected error:", err)
	} else {
		file.Close() //nolint:errcheck
	}

	if err := store.Check(); err == nil {
		t.Fatalf("check should return an error if path is not a directory")
	}

	if err := os.Remove(testBaseDir); err != nil {
		t.Fatal("unexpected error:", err)
	}
	if err := os.Mkdir(testBaseDir, 0000); err != nil {
		t.Fatal("unexpected error:", err)
	}
	defer os.RemoveAll(testBaseDir) //nolint:errcheck

	if err := store.Check(); err == nil {
		t.Fatalf("check should return an error if directory is not accessible")
	}

	if err := os.Chmod(testBaseDir, 0755); err != nil {
		t.Fatal("unexpected error:", err)
	}

	if err := store.Check(); err == nil {
		t.Fatalf("check should return an error for an empty directory")
	}

	// Initialize the store's default parameter set
	if err := ensureDefaultParameterSet(store); err != nil {
		t.Fatal("Unexpected error:", err)
	}

	if err := store.Init("admin", "admin"); err != nil {
		t.Fatal("init should succeed on an empty directory:", err)
	}

	if err := store.Check(); err != nil {
		t.Fatal("check should succeed in a freshly-created base:", err)
	}

	if err := os.RemoveAll(filepath.Join(testBaseDir, ".tmp")); err != nil {
		t.Fatal("Unexpected error:", err)
	}

	if err := store.Check(); err != nil {
		t.Fatal("check should succeed without .tmp/:", err)
	}

	if err := store.AddUser("foo", "bar", false); err != nil {
		t.Fatal("unexpected error:", err)
	}
	if err := store.Check(); err != nil {
		t.Fatal("check should succeed after adding regular user:", err)
	}

	// invalid userhash filenames
	if file, err := os.Create(filepath.Join(testBaseDir, "blub")); err != nil {
		t.Fatal("unexpected error:", err)
	} else {
		file.Close() //nolint:errcheck
	}
	if err := store.Check(); err == nil {
		t.Fatal("check should fail if a file with no extension is found")
	}
	if err := os.Remove(filepath.Join(testBaseDir, "blub")); err != nil {
		t.Fatal("unexpected error:", err)
	}

	if file, err := os.Create(filepath.Join(testBaseDir, "blub.invalid")); err != nil {
		t.Fatal("unexpected error:", err)
	} else {
		file.Close() //nolint:errcheck
	}
	if err := store.Check(); err == nil {
		t.Fatal("check should fail if a file with invalid extension is found")
	}
	if err := os.Remove(filepath.Join(testBaseDir, "blub.invalid")); err != nil {
		t.Fatal("unexpected error:", err)
	}

	if file, err := os.Create(filepath.Join(testBaseDir, "admin.user")); err != nil {
		t.Fatal("unexpected error:", err)
	} else {
		file.Close() //nolint:errcheck
	}
	if err := store.Check(); err == nil {
		t.Fatal("check should fail if admin and user hash for the same user exist")
	}
	if err := os.Remove(filepath.Join(testBaseDir, "admin.user")); err != nil {
		t.Fatal("unexpected error:", err)
	}

	if file, err := os.Create(filepath.Join(testBaseDir, "foo.admin")); err != nil {
		t.Fatal("unexpected error:", err)
	} else {
		file.Close() //nolint:errcheck
	}
	if err := store.Check(); err == nil {
		t.Fatal("check should fail if admin and user hash for the same user exist")
	}
	if err := os.Remove(filepath.Join(testBaseDir, "foo.admin")); err != nil {
		t.Fatal("unexpected error:", err)
	}

	// TODO: add more tests
}

func TestAddUser(t *testing.T) {
	adminuser := "root"
	password := "verysecret"

	store := NewDir(testBaseDir)

	if err := os.Mkdir(testBaseDir, 0755); err != nil {
		t.Fatal("unexpected error:", err)
	}
	defer os.RemoveAll(testBaseDir) //nolint:errcheck

	if err := ensureDefaultParameterSet(store); err != nil {
		t.Fatal("Unexpected error:", err)
	}

	if err := store.Init(adminuser, password); err != nil {
		t.Fatal("unexpected error:", err)
	}

	users := []struct {
		name  string
		valid bool
	}{
		{"", false},
		{"_", false},
		{"hugo", true},
		{"hugo%", false},
		{"@hugo", false},
		{"hugo@example.com", true},
		{"my_Name", true},
		{"WhyHasn'tAnybodyWrittenThisYet", false},
		{"WhyHasn_tAnybodyWrittenThisY@", true},
		{"hello_SPAMMERS@my-domain.net", true},
	}

	for _, u := range users {
		err := store.AddUser(u.name, password, false)
		if u.valid && err != nil {
			t.Fatalf("AddUser returned and unexpected error for '%s': %v", u.name, err)
		} else if !u.valid && err == nil {
			t.Fatalf("AddUser didn't return an error for ivalid user '%s'", u.name)
		}
	}
}

func TestListFull(t *testing.T) {
	adminuser := "root"
	password := "verysecret"
	user1 := "test"
	password1 := "secret"

	store := NewDir(testBaseDir)

	if err := os.Mkdir(testBaseDir, 0755); err != nil {
		t.Fatal("unexpected error:", err)
	}
	defer os.RemoveAll(testBaseDir) //nolint:errcheck

	if list, err := store.ListFull(); err != nil {
		t.Fatal("unexpected error:", err)
	} else if len(list) != 0 {
		t.Fatalf("listFull should return an empty user list for an empty directory")
	}

	if err := ensureDefaultParameterSet(store); err != nil {
		t.Fatal("Unexpected error:", err)
	}

	if err := store.Init(adminuser, password); err != nil {
		t.Fatal("unexpected error:", err)
	}

	if list, err := store.ListFull(); err != nil {
		t.Fatal("unexpected error:", err)
	} else if len(list) != 1 {
		t.Fatalf("list should return a list of length 1")
	} else {
		if user, ok := list[adminuser]; !ok || !user.IsAdmin || !user.IsValid || !user.IsSupported || user.FormatID != store.Params[store.Default].GetFormatID() {
			t.Fatalf("list returned wrong user list: %v", user)
		}
	}

	if err := store.AddUser(user1, password1, false); err != nil {
		t.Fatal("unexpected error:", err)
	}

	if list, err := store.ListFull(); err != nil {
		t.Fatal("unexpected error:", err)
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
	defer os.RemoveAll(testBaseDir) //nolint:errcheck

	if list, err := store.List(); err != nil {
		t.Fatal("unexpected error:", err)
	} else if len(list) != 0 {
		t.Fatalf("list should return an empty user list for an empty directory")
	}

	if err := ensureDefaultParameterSet(store); err != nil {
		t.Fatal("Unexpected error:", err)
	}

	if err := store.Init(adminuser, password); err != nil {
		t.Fatal("unexpected error:", err)
	}

	if list, err := store.List(); err != nil {
		t.Fatal("unexpected error:", err)
	} else if len(list) != 1 {
		t.Fatalf("list should return a list of length 1")
	} else {
		if user, ok := list[adminuser]; !ok || !user.IsAdmin {
			t.Fatalf("list returned wrong user list")
		}
	}

	if err := store.AddUser(user1, password1, false); err != nil {
		t.Fatal("unexpected error:", err)
	}

	if list, err := store.List(); err != nil {
		t.Fatal("unexpected error:", err)
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
		t.Fatal("unexpected error:", err)
	}

	if list, err := store.List(); err != nil {
		t.Fatal("unexpected error:", err)
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

	if err := ensureDefaultParameterSet(testStoreUserHash); err != nil {
		fmt.Println("Error initializing default parameter set:", err)
		os.Exit(-1)
	}

	ret := m.Run()

	if err := os.RemoveAll(testBaseDirUserHash); err != nil {
		fmt.Println("Error removing store base directory:", err)
	}
	os.Exit(ret)
}
