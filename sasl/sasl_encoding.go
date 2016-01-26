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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	// MaxRequestLength is the maximum length allowed for login, password
	// service and realm
	MaxRequestLength = 256
)

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
		return 0, nil, fmt.Errorf("message part exceeds maximum length %d > %d", strlen, MaxRequestLength)
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

func decodeLengthEncodedStrings(reader io.Reader, parts []string) error {
	scanner := bufio.NewScanner(reader)
	scanner.Split(scanLengthEncodedString)

	var i = 0
	for scanner.Scan() {
		if i >= len(parts) {
			return errors.New("too many parts in message")
		}
		parts[i] = string(scanner.Bytes()[2:])
		i += 1
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if i < len(parts) {
		return errors.New("too few parts in message")
	}
	return nil
}

func encodeLengthEncodedStrings(writer io.Writer, parts []string) error {
	for _, part := range parts {
		if len(part) > math.MaxUint16 {
			return errors.New("part is too long")
		}

		data := make([]byte, 2+len(part))
		binary.BigEndian.PutUint16(data, uint16(len(part)))
		copy(data[2:], []byte(part))
		if _, err := writer.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// Request contains all values for a saslauthd authentication request.
type Request struct {
	Login    string
	Password string
	Service  string
	Realm    string
}

// Decode reads a request from reader and decodes it.
func (r *Request) Decode(reader io.Reader) (err error) {
	parts := make([]string, 4)
	if err := decodeLengthEncodedStrings(reader, parts); err != nil {
		return err
	}
	if len(parts[0]) == 0 {
		return errors.New("empty login is not allowed")
	}
	if len(parts[1]) == 0 {
		return errors.New("empty password is not allowed")
	}

	r.Login = parts[0]
	r.Password = parts[1]
	r.Service = parts[2]
	r.Realm = parts[3]
	return
}

// Encode encodes and writes a request to writer.
func (r *Request) Encode(writer io.Writer) error {
	parts := make([]string, 4)
	if len(r.Login) > MaxRequestLength {
		return errors.New("Login is too long")
	}
	parts[0] = r.Login

	if len(r.Password) > MaxRequestLength {
		return errors.New("Password is too long")
	}
	parts[1] = r.Password

	if len(r.Service) > MaxRequestLength {
		return errors.New("Service is too long")
	}
	parts[2] = r.Service

	if len(r.Realm) > MaxRequestLength {
		return errors.New("Realm is too long")
	}
	parts[3] = r.Realm

	return encodeLengthEncodedStrings(writer, parts)
}

// Marshal encodes the request values into a byte slice. The format is
// compatible to the requests as expected by salsauthd.
func (r *Request) Marshal() (data []byte, err error) {
	buf := bytes.NewBuffer(data)
	err = r.Encode(buf)
	return
}

// Unmarshal decodes the request values from it's byte representaion.
func (r *Request) Unmarshal(data []byte) (err error) {
	buf := bytes.NewBuffer(data)
	err = r.Decode(buf)
	return
}

// Response holds the result as well as the message as returned by the
// authentication provider.
type Response struct {
	Result  bool
	Message string
}

// Decode reads a response from reader and decodes it.
func (r *Response) Decode(reader io.Reader) (err error) {
	r.Result = false
	parts := make([]string, 1)
	if err := decodeLengthEncodedStrings(reader, parts); err != nil {
		return err
	}
	if len(parts[0]) == 0 {
		return errors.New("response is empty")
	}
	if len(parts[0]) >= 2 {
		switch parts[0][0:2] {
		case "OK":
			r.Result = true
		case "NO":
			r.Result = false
		default:
			return errors.New("response is invalid")
		}
	}
	if len(parts[0]) > 3 {
		r.Message = parts[0][3:]
	}
	return
}

// Encode encodes and writes a response to writer.
func (r *Response) Encode(writer io.Writer) error {
	parts := make([]string, 1)
	if r.Result {
		parts[0] = "OK"
	} else {
		parts[0] = "NO"
	}
	if r.Message != "" {
		parts[0] += " " + r.Message
	}
	return encodeLengthEncodedStrings(writer, parts)
}

// Marshal encodes the response into a byte slice. The format is the same
// as used by salsauthd.
func (r *Response) Marshal() (data []byte, err error) {
	buf := bytes.NewBuffer(data)
	err = r.Encode(buf)
	return
}

// Unmarshal decodes the response from the it's byte representaion.
func (r *Response) Unmarshal(data []byte) (err error) {
	buf := bytes.NewBuffer(data)
	err = r.Decode(buf)
	return
}
