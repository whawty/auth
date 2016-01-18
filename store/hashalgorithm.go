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
// * Neither the name of whawty nor the names of its
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

package whawty

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/scrypt"
)

// TODO: make this configurable?
const (
	hNe      uint = 14
	hN       int  = 1 << hNe
	hr       int  = 8
	hp       int  = 1
	hsaltlen int  = 16
	hkeylen  int  = 32
)

func CalcHash(password string) (hash string, err error) {
	salt := make([]byte, hsaltlen)
	if _, err = rand.Read(salt); err != nil {
		return
	}
	var key []byte
	if key, err = scrypt.Key([]byte(password), salt, hN, hr, hp, hkeylen); err != nil {
		return
	}

	// TODO: create hash string compatible to libsodium
	params := fmt.Sprintf("%04X%02X%02X", hNe, hr, hp)
	salt64 := base64.StdEncoding.EncodeToString(salt)
	key64 := base64.StdEncoding.EncodeToString(key)
	hash = fmt.Sprintf("$s0$%s$%s$%s", params, salt64, key64)
	return
}

func CheckHash(hash, password string) (ok bool, err error) {
	// TODO: parse paremeter from hash string and compare with computed key
	ok = false
	return
}
