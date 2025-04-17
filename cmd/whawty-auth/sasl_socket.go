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
	"net"
	"os"

	"github.com/whawty/auth/sasl"
)

func callback(login, password, service, realm, path string, store *Store) (ok bool, msg string, err error) {
	wdl.Printf("auth request on '%s': [user=%s] [service=%s] [realm=%s]", path, login, service, realm)

	ok, _, _, err = store.Authenticate(login, password)
	if err != nil {
		return false, "", err
	}
	if ok {
		msg = "successfully authenticated"
	} else {
		msg = "wrong credentials"
	}

	return ok, msg, nil
}

func runSaslAuthSocket(path string, store *Store) error {
	os.Remove(path) //nolint:errcheck
	s, err := sasl.NewServer(path, func(log string, pwd string, srv string, rlm string) (bool, string, error) {
		return callback(log, pwd, srv, rlm, path, store)
	})
	if err != nil {
		return err
	}
	wl.Printf("listening on '%s'", path)

	defer os.Remove(path) //nolint:errcheck
	if err := s.Run(); err != nil {
		wl.Printf("error on sasl socket '%s': %s", path, err)
	}
	return nil
}

func runSaslAuthSocketListener(listener *net.UnixListener, store *Store) error {
	path := listener.Addr().String()
	s, err := sasl.NewServerFromListener(listener, func(log string, pwd string, srv string, rlm string) (bool, string, error) {
		return callback(log, pwd, srv, rlm, path, store)
	})
	if err != nil {
		return err
	}
	wl.Printf("listening on '%s'", path)

	if err := s.Run(); err != nil {
		wl.Printf("error on sasl socket '%s': %s", path, err)
	}
	return nil
}
