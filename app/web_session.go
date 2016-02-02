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

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

type webSessionFactory struct {
	key []byte
}

func newWebSessionFactory() (w *webSessionFactory, err error) {
	w = &webSessionFactory{}
	w.key = make([]byte, sha256.Size)

	var keylen int
	if keylen, err = rand.Read(w.key); keylen != len(w.key) {
		return nil, fmt.Errorf("Insufficient random bytes for web session key")
	}
	if err != nil {
		return
	}
	return
}

func (w *webSessionFactory) generate(username string, isAdmin bool) (status int, session, errorStr string) {
	token := fmt.Sprintf("%s:%t:%d", username, isAdmin, time.Now().Unix())
	mac := hmac.New(sha256.New, w.key)
	if _, err := mac.Write([]byte(token)); err != nil {
		status = http.StatusInternalServerError
		errorStr = err.Error()
		return
	}

	b64mac := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	session = fmt.Sprintf("%s:%s", token, b64mac)
	status = http.StatusOK
	return
}

func (w *webSessionFactory) check(session string) (status int, ok bool, username string, isAdmin bool, errorStr string) {
	// TODO: check session and return username, admin status
	return
}
