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

package sasl

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const (
	testBaseDir string = "test-sasl"

	testUsername string = "foo"
	testPassword string = "bar"
	testService  string = "whawty"
	testRealm    string = "test"

	errorService string = "error"
)

func callback(login, password, service, realm string) (ok bool, msg string, err error) {
	if service == errorService {
		return true, "success", errors.New("it is an error to use the error service")
	}

	ok = false
	if service != testService {
		return false, "wrong service", nil
	}
	if realm != testRealm {
		return false, "wrong realm", nil
	}

	if login == testUsername {
		if password == testPassword {
			ok = true
			msg = "success"
		} else {
			msg = "invalid password"
		}
	} else {
		msg = "unknown user: " + login
	}

	return ok, msg, nil
}

func TestCreateServer(t *testing.T) {
	if _, err := NewServer(filepath.Join(testBaseDir, "new.sock"), callback); err == nil {
		t.Fatalf("initializing a server socket inside non-existing directory should give an error")
	}

	if err := os.Mkdir(testBaseDir, 0755); err != nil {
		t.Fatal("unexpected error:", err)
	}
	defer os.RemoveAll(testBaseDir) //nolint:errcheck

	if _, err := NewServer(filepath.Join(testBaseDir, "new.sock"), callback); err != nil {
		t.Fatal("unexpected error:", err)
	}

	ln, err := net.Listen("unix", filepath.Join(testBaseDir, "existing.sock"))
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	if _, err := NewServerFromListener(ln.(*net.UnixListener), callback); err != nil {
		t.Fatal("unexpected error:", err)
	}
}

func TestRunReturnsNilAfterClose(t *testing.T) {
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "close.sock"))
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	s, err := NewServerFromListener(ln.(*net.UnixListener), callback)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	done := make(chan error, 1)
	go func() { done <- s.Run() }()

	if err := ln.Close(); err != nil {
		t.Fatal("unexpected error:", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("Run() returned an error after the listener was closed:", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after the listener was closed")
	}
}

// fakeListener returns the errors in errs from consecutive calls to Accept()
// and net.ErrClosed once errs is exhausted.
type fakeListener struct {
	errs  []error
	calls int
}

func (l *fakeListener) Accept() (net.Conn, error) {
	l.calls++
	if len(l.errs) == 0 {
		return nil, net.ErrClosed
	}
	err := l.errs[0]
	l.errs = l.errs[1:]
	return nil, err
}

func (l *fakeListener) Close() error   { return nil }
func (l *fakeListener) Addr() net.Addr { return &net.UnixAddr{Name: "fake.sock", Net: "unix"} }

func acceptError(errno syscall.Errno) error {
	return &net.OpError{Op: "accept", Net: "unix", Err: os.NewSyscallError("accept4", errno)}
}

func TestRunRetriesTemporaryErrors(t *testing.T) {
	ln := &fakeListener{errs: []error{acceptError(syscall.EMFILE), acceptError(syscall.ENFILE), acceptError(syscall.ECONNABORTED)}}
	s := &Server{sockPath: "fake.sock", cb: callback, ln: ln}

	start := time.Now()
	if err := s.Run(); err != nil {
		t.Fatal("unexpected error:", err)
	}
	if ln.calls != 4 {
		t.Fatalf("Accept() was called %d times, expected 4", ln.calls)
	}
	// retries after 5ms, 10ms and 20ms
	if elapsed := time.Since(start); elapsed < 35*time.Millisecond {
		t.Fatalf("Run() retried too fast: all retries took %s, expected at least 35ms", elapsed)
	}
}

func TestRunReturnsPermanentErrors(t *testing.T) {
	ln := &fakeListener{errs: []error{acceptError(syscall.EINVAL)}}
	s := &Server{sockPath: "fake.sock", cb: callback, ln: ln}

	err := s.Run()
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Run() returned %v, expected EINVAL", err)
	}
	if ln.calls != 1 {
		t.Fatalf("Accept() was called %d times, expected 1", ln.calls)
	}
}

func TestClientAuthUnreachableSocket(t *testing.T) {
	c := NewClient(filepath.Join(testBaseDir, "nonexstend.sock"))
	if _, _, err := c.Auth(testUsername, testPassword, testService, testRealm); err == nil {
		t.Fatalf("trying to authenticate against non-existing socket should give an error")
	}
}

func TestAuthentication(t *testing.T) {
	if err := os.Mkdir(testBaseDir, 0755); err != nil {
		t.Fatal("unexpected error:", err)
	}
	defer os.RemoveAll(testBaseDir) //nolint:errcheck

	s, err := NewServer(filepath.Join(testBaseDir, "sock"), callback)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	go func() {
		err := s.Run()
		if err != nil {
			t.Error("unexpected error:", err)
		}
	}()

	c := NewClient(filepath.Join(testBaseDir, "sock"))

	testVectors := []struct {
		username string
		password string
		service  string
		realm    string
		ok       bool
		msg      string
	}{
		{testUsername, testPassword, testService, testRealm, true, "success"},
		{"nobody", testPassword, testService, testRealm, false, "unknown user: nobody"},
		{testUsername, "wrong", testService, testRealm, false, "invalid password"},
		{testUsername, testPassword, "other", testRealm, false, "wrong service"},
		{testUsername, testPassword, "", testRealm, false, "wrong service"},
		{testUsername, testPassword, testService, "blub", false, "wrong realm"},
		{testUsername, testPassword, testService, "", false, "wrong realm"},
		{"", testPassword, testService, testRealm, false, ""},
		{testUsername, "", testService, testRealm, false, ""},
		{testUsername, testPassword, errorService, testRealm, false, "it is an error to use the error service"},
	}

	for _, vector := range testVectors {
		ok, msg, err := c.Auth(vector.username, vector.password, vector.service, vector.realm)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}
		if ok != vector.ok {
			t.Fatal("authentication failed")
		}
		if vector.msg != "" && msg != vector.msg {
			t.Fatal("unexpected message:", msg)
		}
	}
}
