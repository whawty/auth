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
	"gopkg.in/spreadspace/scryptauth.v2"
	"io/ioutil"
	"os"
	"testing"
)

const (
	testBaseDirUserHash string = "test-store-user"
	testBaseDir         string = "test-store"
)

var (
	testStoreUserHash *Dir
)

func TestDirFromConfig(t *testing.T) {
	jsonData := []struct {
		s     string
		valid bool
	}{
		{"", false},
		{"{}", false},
		{"{ \"basedir\": \"/tmp\" }", true},
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

func TestMain(m *testing.M) {
	if err := os.Mkdir(testBaseDirUserHash, 0755); err != nil {
		fmt.Println("Error creating store base directory:", err)
		os.Exit(-1)
	}

	testStoreUserHash = NewDir(testBaseDirUserHash)
	testStoreUserHash.DefaultCtxID = 1
	ctx, _ := scryptauth.New(14, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	testStoreUserHash.Contexts[testStoreUserHash.DefaultCtxID] = ctx

	ret := m.Run()

	if err := os.RemoveAll(testBaseDirUserHash); err != nil {
		fmt.Println("Error removing store base directory:", err)
	}
	os.Exit(ret)
}
