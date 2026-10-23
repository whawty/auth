//
// Copyright (c) 2026 whawty contributors (see AUTHORS file)
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
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func newTestSessionFactory(t *testing.T, lifetime time.Duration) *webSessionFactory {
	t.Helper()
	f, err := NewWebSessionFactory(lifetime)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	return f
}

// sealTestToken builds a session from an arbitrary token, the same way
// Generate() does it for "<username>:<admin>:<unix-time>".
func sealTestToken(t *testing.T, f *webSessionFactory, token string) string {
	t.Helper()
	status, errStr, nonce, enctoken := f.sealToken(token)
	if status != http.StatusOK {
		t.Fatalf("sealing token %q failed: %s", token, errStr)
	}
	return base64.URLEncoding.EncodeToString(nonce) + ":" + base64.URLEncoding.EncodeToString(enctoken)
}

func generateTestSession(t *testing.T, f *webSessionFactory, username string, isAdmin bool) string {
	t.Helper()
	status, errStr, session := f.Generate(username, isAdmin)
	if status != http.StatusOK {
		t.Fatalf("Generate(%q, %t) failed: %d %s", username, isAdmin, status, errStr)
	}
	if session == "" {
		t.Fatalf("Generate(%q, %t) returned an empty session", username, isAdmin)
	}
	return session
}

func expectSessionStatus(t *testing.T, f *webSessionFactory, session string, want int) {
	t.Helper()
	status, errStr, username, isAdmin := f.Check(session)
	if status != want {
		t.Errorf("Check(%q) = %d (%s), want %d", session, status, errStr, want)
	}
	if status != http.StatusOK && (username != "" || isAdmin) {
		t.Errorf("Check(%q) failed but still returned username %q and admin %t", session, username, isAdmin)
	}
}

func TestSessionRoundTrip(t *testing.T) {
	f := newTestSessionFactory(t, time.Minute)
	for _, tc := range []struct {
		username string
		isAdmin  bool
	}{
		{"alice", false},
		{"equinox", true},
		{"mail.relay@example.org", false},
		{"0-backup_agent", true},
	} {
		session := generateTestSession(t, f, tc.username, tc.isAdmin)
		status, errStr, username, isAdmin := f.Check(session)
		if status != http.StatusOK {
			t.Errorf("Check() of a fresh session for %q failed: %d %s", tc.username, status, errStr)
			continue
		}
		if username != tc.username || isAdmin != tc.isAdmin {
			t.Errorf("Check() = (%q, %t), want (%q, %t)", username, isAdmin, tc.username, tc.isAdmin)
		}
	}
}

func TestSessionsAreUnique(t *testing.T) {
	f := newTestSessionFactory(t, time.Minute)
	seen := map[string]bool{}
	for range 100 {
		session := generateTestSession(t, f, "alice", false)
		if seen[session] {
			t.Fatalf("Generate() returned the same session twice: %q", session)
		}
		seen[session] = true
	}
}

func TestSessionFromOtherFactoryIsRejected(t *testing.T) {
	f1 := newTestSessionFactory(t, time.Minute)
	f2 := newTestSessionFactory(t, time.Minute)
	expectSessionStatus(t, f2, generateTestSession(t, f1, "equinox", true), http.StatusUnauthorized)
}

func TestTamperedSessionIsRejected(t *testing.T) {
	f := newTestSessionFactory(t, time.Minute)
	session := generateTestSession(t, f, "alice", false)
	parts := strings.SplitN(session, ":", 2)
	nonce, _ := base64.URLEncoding.DecodeString(parts[0])
	enctoken, _ := base64.URLEncoding.DecodeString(parts[1])
	encode := func(nonce, enctoken []byte) string {
		return base64.URLEncoding.EncodeToString(nonce) + ":" + base64.URLEncoding.EncodeToString(enctoken)
	}

	// flip one bit in every byte of the encrypted token, one at a time
	for i := range enctoken {
		tampered := append([]byte{}, enctoken...)
		tampered[i] ^= 0x01
		expectSessionStatus(t, f, encode(nonce, tampered), http.StatusUnauthorized)
	}
	// same for the nonce
	for i := range nonce {
		tampered := append([]byte{}, nonce...)
		tampered[i] ^= 0x01
		expectSessionStatus(t, f, encode(tampered, enctoken), http.StatusUnauthorized)
	}
	// encrypted token with the nonce of another session
	other := strings.SplitN(generateTestSession(t, f, "alice", false), ":", 2)
	expectSessionStatus(t, f, other[0]+":"+parts[1], http.StatusUnauthorized)
	// truncated encrypted token
	expectSessionStatus(t, f, encode(nonce, enctoken[:len(enctoken)-1]), http.StatusUnauthorized)
	expectSessionStatus(t, f, encode(nonce, nil), http.StatusUnauthorized)
}

func TestMalformedSessionIsRejected(t *testing.T) {
	f := newTestSessionFactory(t, time.Minute)
	valid := strings.SplitN(generateTestSession(t, f, "alice", false), ":", 2)
	b64 := base64.URLEncoding.EncodeToString

	for _, session := range []string{
		"",
		"no-separator",
		"!!!:" + valid[1],                      // nonce is not base64
		valid[0] + ":!!!",                      // encrypted token is not base64
		":" + valid[1],                         // empty nonce
		b64([]byte("abcd")) + ":" + valid[1],   // nonce too short
		b64(make([]byte, 64)) + ":" + valid[1], // nonce too long
	} {
		expectSessionStatus(t, f, session, http.StatusBadRequest)
	}
}

func TestSessionLifetime(t *testing.T) {
	f := newTestSessionFactory(t, 10*time.Minute)
	token := func(age time.Duration) string {
		return sealTestToken(t, f, fmt.Sprintf("alice:false:%d", time.Now().Add(-age).Unix()))
	}

	expectSessionStatus(t, f, token(0), http.StatusOK)
	expectSessionStatus(t, f, token(9*time.Minute), http.StatusOK)
	expectSessionStatus(t, f, token(11*time.Minute), http.StatusUnauthorized)
	expectSessionStatus(t, f, token(24*time.Hour), http.StatusUnauthorized)
	expectSessionStatus(t, f, token(-time.Minute), http.StatusBadRequest) // from the future
}

func TestInvalidTokenContentIsRejected(t *testing.T) {
	f := newTestSessionFactory(t, time.Minute)
	now := time.Now().Unix()
	for _, token := range []string{
		"",
		"alice",
		"alice:true",
		fmt.Sprintf("alice:yes:%d", now),
		fmt.Sprintf("alice:TRUE:%d", now),
		fmt.Sprintf("alice::%d", now),
		"alice:true:",
		"alice:true:soon",
		fmt.Sprintf("alice:true:%d.5", now),
	} {
		expectSessionStatus(t, f, sealTestToken(t, f, token), http.StatusBadRequest)
	}
}

// Usernames can't contain ':' (see store.AddUser), but even if they did
// the session must not turn into an admin session.
func TestUsernameWithSeparatorDoesNotGrantAdmin(t *testing.T) {
	f := newTestSessionFactory(t, time.Minute)
	session := generateTestSession(t, f, "mallory:true", false)
	status, _, username, isAdmin := f.Check(session)
	if status == http.StatusOK && isAdmin {
		t.Fatalf("session for non-admin user %q was accepted as admin session of %q", "mallory:true", username)
	}
}
