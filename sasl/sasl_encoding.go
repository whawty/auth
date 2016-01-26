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

// Package sasl implements the authentication protocol as used by salsauthd.
package sasl

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// MaxRequestLength is the maximum length allowed for login, password
	// service and realm
	MaxRequestLength = 256
)

// Request contains all values for a saslauthd authentication request.
type Request struct {
	Login    string
	Password string
	Service  string
	Realm    string
}

// Marshal encodes the request values into a byte slice. The format is
// compatible to the requests as expected by salsauthd.
func (r *Request) Marshal() (data []byte, err error) {
	// TODO: implemente this
	return
}

// Unmarshal decodes the request values from it's byte representaion.
func (r *Request) Unmarshal(data []byte) (err error) {
	// TODO: implemente this
	return
}

type RequestDecoder struct {
	scanner *bufio.Scanner
}

func scanLengthEncodedString(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil // no more data
	}

	if len(data) < 2 {
		if atEOF {
			return 0, nil, errors.New("message is invalid")
		}
		return 0, nil, nil // need more data to parse length
	}
	strlen := int(binary.BigEndian.Uint16(data[0:2])) // get string length (network-byte-order == big-endian)

	if strlen > MaxRequestLength {
		return 0, nil, fmt.Errorf("message parameter exceeds maximum length %d > %d", strlen, MaxRequestLength)
	}
	if strlen == 0 {
		return 2, data[0:2], nil // scan will drop empty tokens so keep the length as part of it ???
	}

	if len(data[2:]) < strlen {
		if atEOF {
			return 0, nil, errors.New("message is too short")
		}
		return 0, nil, nil // need more data to parse whole string
	}
	return strlen + 2, data[0 : strlen+2], nil // scan will drop empty tokens so keep the length as part of it ???
}

func NewRequestDecoder(r io.Reader) (d *RequestDecoder) {
	d = &RequestDecoder{}
	d.scanner = bufio.NewScanner(r)
	d.scanner.Split(scanLengthEncodedString)
	return
}

func (d *RequestDecoder) Decode(r *Request) error {
	data := make([]string, 4)
	var i = 0
	for d.scanner.Scan() {
		if i >= len(data) {
			return errors.New("too many parameters in message")
		}
		data[i] = string(d.scanner.Bytes()[2:])
		i += 1
	}
	if err := d.scanner.Err(); err != nil {
		return err
	}
	if i < len(data) {
		return errors.New("too few parameters in message")
	}
	r.Login = data[0]
	r.Password = data[1]
	r.Service = data[2]
	r.Realm = data[3]
	return nil
}

// Response holds the result as well as the message as returned by the
// authentication provider.
type Response struct {
	Result  bool
	Message string
}

// Marshal encodes the response into a byte slice. The format is the same
// as used by salsauthd.
func (r *Response) Marshal() (data []byte, err error) {
	// TODO: implemente this
	return
}

// Unmarshal decodes the response from the it's byte representaion.
func (r *Response) Unmarshal(data []byte) (err error) {
	// TODO: implemente this
	return
}
