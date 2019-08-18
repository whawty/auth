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

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type webSessionFactory struct {
	aesgcm   cipher.AEAD
	lifetime time.Duration
}

func NewWebSessionFactory(lifetime time.Duration) (w *webSessionFactory, err error) {
	w = &webSessionFactory{}
	w.lifetime = lifetime

	key := make([]byte, 16) // -> AES-128
	var keylen int
	if keylen, err = rand.Read(key); keylen != len(key) || err != nil {
		if err == nil {
			err = fmt.Errorf("insufficient random bytes for web session key")
		}
		return
	}

	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	if w.aesgcm, err = cipher.NewGCM(block); err != nil {
		return
	}

	return
}

func (w *webSessionFactory) sealToken(token string) (status int, errorStr string, nonce, enctoken []byte) {
	nonce = make([]byte, w.aesgcm.NonceSize())
	if noncelen, err := rand.Read(nonce); noncelen != len(nonce) || err != nil {
		status = http.StatusInternalServerError
		errorStr = "sealing session data failed"
		if err != nil {
			errorStr += ": " + err.Error()
		}
		return
	}

	enctoken = w.aesgcm.Seal(nil, nonce, []byte(token), nil)
	status = http.StatusOK
	return
}

func (w *webSessionFactory) openToken(nonce, enctoken []byte) (status int, errorStr string, token string) {
	tokendata, err := w.aesgcm.Open(nil, nonce, enctoken, nil)
	if err != nil {
		status = http.StatusUnauthorized
		errorStr = err.Error()
		return
	}

	token = string(tokendata)
	status = http.StatusOK
	return
}

func (w *webSessionFactory) splitCheckToken(token string) (status int, errorStr string, username string, isAdmin bool) {
	tmp := strings.SplitN(token, ":", 3)
	if len(tmp) != 3 {
		status = http.StatusBadRequest
		errorStr = "invalid session token"
		return
	}

	username = tmp[0]

	switch tmp[1] {
	case "true":
		isAdmin = true
	case "false":
		isAdmin = false
	default:
		status = http.StatusBadRequest
		errorStr = "invalid session token"
		return
	}

	tmpTime, err := strconv.ParseInt(tmp[2], 10, 64)
	if err != nil {
		status = http.StatusBadRequest
		errorStr = fmt.Sprintf("invalid session token: %v", err)
		return
	}
	st := time.Unix(tmpTime, 0)
	age := time.Since(st)
	if age < 0 {
		status = http.StatusBadRequest
		errorStr = "session token is from the future."
		return
	}
	if age > w.lifetime {
		status = http.StatusUnauthorized
		errorStr = "session timed out."
		return
	}

	status = http.StatusOK
	return
}

func (w *webSessionFactory) Generate(username string, isAdmin bool) (status int, errorStr, session string) {
	token := fmt.Sprintf("%s:%t:%d", username, isAdmin, time.Now().Unix())

	var nonce, enctoken []byte
	status, errorStr, nonce, enctoken = w.sealToken(token)
	if status != http.StatusOK {
		return
	}
	session = fmt.Sprintf("%s:%s", base64.URLEncoding.EncodeToString(nonce), base64.URLEncoding.EncodeToString(enctoken))
	status = http.StatusOK
	return
}

func (w *webSessionFactory) Check(session string) (status int, errorStr string, username string, isAdmin bool) {
	tmp := strings.SplitN(session, ":", 2)
	if len(tmp) != 2 {
		status = http.StatusBadRequest
		errorStr = "invalid session token"
		return
	}

	nonce, err := base64.URLEncoding.DecodeString(tmp[0])
	if err != nil {
		status = http.StatusBadRequest
		errorStr = fmt.Sprintf("invalid session token: %v", err)
		return
	}

	enctoken, err := base64.URLEncoding.DecodeString(tmp[1])
	if err != nil {
		status = http.StatusBadRequest
		errorStr = fmt.Sprintf("invalid session token: %v", err)
		return
	}

	var token string
	status, errorStr, token = w.openToken(nonce, enctoken)
	if status != http.StatusOK {
		return
	}

	return w.splitCheckToken(token)
}
