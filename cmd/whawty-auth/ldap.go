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
	"crypto/tls"
	"net"

	"github.com/glauth/ldap"
)

type ldapHandler struct {
	store *Store
}

func (h ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	if ok, _, _, _ := h.store.Authenticate(bindDN, bindSimplePw); !ok {
		return ldap.LDAPResultInvalidCredentials, nil
	}
	return ldap.LDAPResultSuccess, nil
}

func runLDAPsListener(listener *net.TCPListener, config *ldapsConfig, store *Store) error {
	server := ldap.NewServer()
	server.BindFunc("", ldapHandler{store: store})

	tlsConfig, err := config.TLS.ToGoTLSConfig()
	if err != nil {
		return err
	}
	wl.Printf("ldap: listening on '%s' using TLS", listener.Addr())
	return server.Serve(tls.NewListener(listener, tlsConfig))
}

func runLDAPsAddr(addr string, config *ldapsConfig, store *Store) error {
	if addr == "" {
		addr = ":ldaps"
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return runLDAPsListener(listener.(*net.TCPListener), config, store)
}

func runLDAPListener(listener *net.TCPListener, config *ldapConfig, store *Store) (err error) {
	server := ldap.NewServer()
	server.BindFunc("", ldapHandler{store: store})
	if config.TLS != nil {
		if server.TLSConfig, err = config.TLS.ToGoTLSConfig(); err != nil {
			return err
		}
		wl.Printf("ldap: listening on '%s' with StartTLS", listener.Addr())
	} else {
		wl.Printf("ldap: listening on '%s'", listener.Addr())
	}
	return server.Serve(listener)
}

func runLDAPAddr(addr string, config *ldapConfig, store *Store) error {
	if addr == "" {
		addr = ":ldap"
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return runLDAPListener(listener.(*net.TCPListener), config, store)
}
