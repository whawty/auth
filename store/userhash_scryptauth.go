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
	"encoding/base64"
	"fmt"
	"strings"

	"gopkg.in/spreadspace/scryptauth.v2"
)

func scryptAuthDecodeBase64(hashStr string) (salt, hash []byte, err error) {
	parts := strings.Split(hashStr, ":")
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("whawty.auth.store: hash string has invalid format")
	}

	salt, err = base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("whawty.auth.store: decoding hmac-sha256(scrypt) salt failed (%v)", err)
	}
	hash, err = base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("whawty.auth.store: decoding hmac-sha256(scrypt) hash failed (%v)", err)
	}

	return hash, salt, nil
}

func scryptAuthValid(hashStr string) (bool, error) {
	hash, salt, err := scryptAuthDecodeBase64(hashStr)
	if err != nil {
		return false, err
	}

	if len(hash) == 0 || len(salt) == 0 {
		return false, fmt.Errorf("whawty.auth.store: hash has invalid format")
	}
	return true, nil
}

func scryptAuthGen(password string, params *ScryptAuthParameterSet) (string, error) {
	hash, salt, err := params.saCtx.Gen([]byte(password))
	if err != nil {
		return "", err
	}

	hashStr := scryptauth.EncodeBase64(0, hash, salt)
	return hashStr, nil
}

func scryptAuthCheck(password, hashStr string, params *ScryptAuthParameterSet) (isAuthenticated bool, err error) {
	var hash, salt []byte
	if _, hash, salt, err = scryptauth.DecodeBase64(hashStr); err != nil {
		return
	}

	isAuthenticated, err = params.saCtx.Check(hash, []byte(password), salt)
	return
}
