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
)

func scryptauthSupported(hashStr string) (bool, string, error) {
	ctxID, hash, salt, err := scryptauth.DecodeBase64(hashStr)
	if err != nil {
		return false, "", err
	}

	if ctxID == 0 || len(hash) == 0 || len(salt) == 0 {
		return false, "", fmt.Errorf("whawty.auth.store: hash has invalid format")
	}
	params := fmt.Sprintf("context:%d", ctxID)
	return true, params, nil
}

func scryptauthGen(password string, store *Dir) (string, error) {
	ctx, ctxExists := store.Scryptauth.Contexts[store.Scryptauth.DefaultCtxID]
	if !ctxExists {
		return "", fmt.Errorf("whawty.auth.store: the store has no default context")
	}
	hash, salt, err := ctx.Gen([]byte(password))
	if err != nil {
		return "", err
	}

	hashStr := scryptauth.EncodeBase64(store.Scryptauth.DefaultCtxID, hash, salt)
	return hashStr, nil
}

func scryptauthCheck(password, hashStr string, store *Dir) (isAuthenticated, upgradeable bool, err error) {
	var ctxID uint
	var hash, salt []byte
	if ctxID, hash, salt, err = scryptauth.DecodeBase64(hashStr); err != nil {
		return
	}

	ctx, ctxExists := store.Scryptauth.Contexts[ctxID]
	if !ctxExists {
		return false, false, fmt.Errorf("whawty.auth.store: context ID '%d' is unknown", ctxID)
	}

	upgradeable = (store.Scryptauth.DefaultCtxID != ctxID)

	isAuthenticated, err = ctx.Check(hash, []byte(password), salt)
	return
}
