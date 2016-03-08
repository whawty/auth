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

package sasl

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestRequestEncode(t *testing.T) {
	overlongpart := make([]byte, MaxRequestLength+1)
	_, err := rand.Read(overlongpart)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	testvectors := []struct {
		req    Request
		valid  bool
		result []byte
	}{
		{
			Request{}, true,
			[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		},
		{
			Request{Login: "testuser", Password: "secret"}, true,
			[]byte{0x0, 0x8, 0x74, 0x65, 0x73, 0x74, 0x75, 0x73, 0x65, 0x72, 0x0, 0x6, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x0, 0x0, 0x0, 0x0},
		},
		{
			Request{Login: "user", Password: "pass", Service: "svc", Realm: "realm"}, true,
			[]byte{0x0, 0x4, 0x75, 0x73, 0x65, 0x72, 0x0, 0x4, 0x70, 0x61, 0x73, 0x73, 0x0, 0x3, 0x73, 0x76, 0x63, 0x0, 0x5, 0x72, 0x65, 0x61, 0x6c, 0x6d},
		},
		{
			Request{Login: string(overlongpart)}, false,
			nil,
		},
		{
			Request{Password: string(overlongpart)}, false,
			nil,
		},
		{
			Request{Service: string(overlongpart)}, false,
			nil,
		},
		{
			Request{Realm: string(overlongpart)}, false,
			nil,
		},
	}

	for _, vector := range testvectors {
		result, err := vector.req.Marshal()
		if vector.valid {
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			if bytes.Compare(vector.result, result) != 0 {
				t.Fatalf("resulting message is invalid is: '%v', should be '%v'", result, vector.result)
			}
		} else {
			if err == nil {
				t.Fatalf("encoding '%+v' should give an error", vector.req)
			}
		}
	}
}

func TestRequestDecode(t *testing.T) {
	testvectors := []struct {
		result  Request
		valid   bool
		reqdata []byte
	}{
		{
			Request{}, false,
			[]byte{},
		},
		{
			Request{}, false,
			[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		},
		{
			Request{}, false,
			[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		},
		{
			Request{}, false,
			[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		},
		{
			Request{}, false,
			[]byte{0x0, 0x20, 0x01, 0x02, 0x03, 0x04},
		},
		{
			Request{Login: "seppi"}, false,
			[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		},
		{
			Request{Password: "hugo"}, false,
			[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		},
		{
			Request{Login: "testuser", Password: "secret"}, true,
			[]byte{0x0, 0x8, 0x74, 0x65, 0x73, 0x74, 0x75, 0x73, 0x65, 0x72, 0x0, 0x6, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x0, 0x0, 0x0, 0x0},
		},
		{
			Request{Login: "user", Password: "pass", Service: "svc", Realm: "realm"}, true,
			[]byte{0x0, 0x4, 0x75, 0x73, 0x65, 0x72, 0x0, 0x4, 0x70, 0x61, 0x73, 0x73, 0x0, 0x3, 0x73, 0x76, 0x63, 0x0, 0x5, 0x72, 0x65, 0x61, 0x6c, 0x6d},
		},
	}

	for _, vector := range testvectors {
		var result Request
		err := result.Unmarshal(vector.reqdata)
		if vector.valid {
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			if vector.result.Login != result.Login || vector.result.Password != result.Password ||
				vector.result.Service != result.Service || vector.result.Realm != result.Realm {
				t.Fatalf("decoded request is wrong: is '%+v', should be '%+v'", result, vector.result)
			}
		} else {
			if err == nil {
				t.Fatalf("decoding '%+v' should give an error", vector.reqdata)
			}
		}
	}
}

func TestResponseEncode(t *testing.T) {
	testvectors := []struct {
		resp   Response
		valid  bool
		result []byte
	}{
		{
			Response{}, true,
			[]byte{0x0, 0x2, 0x4e, 0x4f},
		},
		{
			Response{Result: true}, true,
			[]byte{0x0, 0x2, 0x4f, 0x4b},
		},
		{
			Response{Result: false, Message: "you outta luck!"}, true,
			[]byte{0x0, 0x12, 0x4e, 0x4f, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x75, 0x74, 0x74, 0x61, 0x20, 0x6c, 0x75, 0x63, 0x6b, 0x21},
		},
		{
			Response{Result: true, Message: "congratulations"}, true,
			[]byte{0x0, 0x12, 0x4f, 0x4b, 0x20, 0x63, 0x6f, 0x6e, 0x67, 0x72, 0x61, 0x74, 0x75, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73},
		},
	}

	for _, vector := range testvectors {
		result, err := vector.resp.Marshal()
		if vector.valid {
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			if bytes.Compare(vector.result, result) != 0 {
				t.Fatalf("resulting message is invalid is: '%v', should be '%v'", result, vector.result)
			}
		} else {
			if err == nil {
				t.Fatalf("encoding '%+v' should give an error", vector.resp)
			}
		}
	}
}

func TestResponseDecode(t *testing.T) {
	testvectors := []struct {
		result   Response
		valid    bool
		respdata []byte
	}{
		{
			Response{}, false,
			[]byte{},
		},
		{
			Response{}, false,
			[]byte{0x0, 0x0},
		},
		{
			Response{}, false,
			[]byte{0x0, 0x0, 0x4e, 0x04f},
		},
		{
			Response{}, true,
			[]byte{0x0, 0x2, 0x4e, 0x04f},
		},
		{
			Response{Result: true}, false,
			[]byte{0x0, 0x2, 0x4f, 0x4f},
		},
		{
			Response{Result: true}, true,
			[]byte{0x0, 0x2, 0x4f, 0x4b},
		},
		{
			Response{Result: true, Message: "!"}, true,
			[]byte{0x0, 0x4, 0x4f, 0x4b, 0x20, 0x21},
		},
		{
			Response{Result: true, Message: "hello"}, true,
			[]byte{0x0, 0x8, 0x4f, 0x4b, 0x20, 0x68, 0x65, 0x6c, 0x6c, 0x6f},
		},
	}

	for _, vector := range testvectors {
		var result Response
		err := result.Unmarshal(vector.respdata)
		if vector.valid {
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			if vector.result.Result != result.Result || vector.result.Message != result.Message {
				t.Fatalf("decoded response is wrong: is '%+v', should be '%+v'", result, vector.result)
			}
		} else {
			if err == nil {
				t.Fatalf("decoding '%+v' should give an error", vector.respdata)
			}
		}
	}
}
