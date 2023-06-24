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
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2IDParams struct {
	Time    uint32 `yaml:"time"`
	Memory  uint32 `yaml:"memory"`
	Threads uint8  `yaml:"threads"`
	Length  uint32 `yaml:"length"`
}

type Argon2IDHasher struct {
	Argon2IDParams
}

func NewArgon2IDHasher(params *Argon2IDParams) (*Argon2IDHasher, error) {
	return &Argon2IDHasher{Argon2IDParams: *params}, nil
}

func argon2IDDecodeBase64(hashStr string) (salt, hash []byte, err error) {
	parts := strings.Split(hashStr, ":")
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("whawty.auth.store: hash string has invalid format")
	}

	salt, err = base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("whawty.auth.store: decoding Argon2id salt failed (%v)", err)
	}
	hash, err = base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("whawty.auth.store: decoding Argon2id hash failed (%v)", err)
	}

	return hash, salt, nil
}

func (h *Argon2IDHasher) GetFormatID() string {
	return "argon2id"
}

func (h *Argon2IDHasher) IsValid(hashStr string) (bool, error) {
	salt, hash, err := argon2IDDecodeBase64(hashStr)
	if err != nil {
		return false, err
	}
	if len(hash) == 0 || len(salt) == 0 {
		return false, fmt.Errorf("whawty.auth.store: hash has invalid format")
	}
	return true, nil
}

func (h *Argon2IDHasher) Generate(password string) (string, error) {
	salt := make([]byte, 16)
	salt_length, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	if salt_length != 16 {
		return "", fmt.Errorf("Insufficient random bytes for salt")
	}

	hash := argon2.IDKey([]byte(password), salt, h.Time, h.Memory, h.Threads, h.Length)

	b64_salt := base64.URLEncoding.EncodeToString(salt)
	b64_hash := base64.URLEncoding.EncodeToString(hash)
	return fmt.Sprintf("%s:%s", b64_salt, b64_hash), nil
}

func (h *Argon2IDHasher) Check(password, hashStr string) (bool, error) {
	hash, salt, err := argon2IDDecodeBase64(hashStr)
	if err != nil {
		return false, err
	}

	cmp := argon2.IDKey([]byte(password), salt, h.Time, h.Memory, h.Threads, h.Length)
	if subtle.ConstantTimeCompare(cmp, hash) != 1 {
		return false, fmt.Errorf("Error: Hash verification failed")
	}
	return true, nil
}
