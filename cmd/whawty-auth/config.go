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
	"fmt"
	"os"

	"github.com/spreadspace/tlsconfig"
	"gopkg.in/yaml.v3"
)

type saslauthdConfig struct {
	Listen []string `yaml:"listen"`
}

type httpConfig struct {
	Listen []string `yaml:"listen"`
}

type httpsConfig struct {
	Listen []string             `yaml:"listen"`
	TLS    *tlsconfig.TLSConfig `yaml:"tls"`
}

type ldapConfig struct {
	Listen []string             `yaml:"listen"`
	TLS    *tlsconfig.TLSConfig `yaml:"tls"`
}

type ldapsConfig struct {
	Listen []string             `yaml:"listen"`
	TLS    *tlsconfig.TLSConfig `yaml:"tls"`
}

type listenerConfig struct {
	SASLAuthd *saslauthdConfig `yaml:"saslauthd"`
	HTTP      *httpConfig      `yaml:"http"`
	HTTPs     *httpsConfig     `yaml:"https"`
	LDAP      *ldapConfig      `yaml:"ldap"`
	LDAPs     *ldapsConfig     `yaml:"ldaps"`
}

func readListenerConfig(configfile string) (*listenerConfig, error) {
	file, err := os.Open(configfile)
	if err != nil {
		return nil, err
	}
	defer file.Close() //nolint:errcheck

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)

	c := &listenerConfig{}
	if err = decoder.Decode(c); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %s", err)
	}
	return c, nil
}
