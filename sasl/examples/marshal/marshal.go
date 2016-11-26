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

	"github.com/whawty/auth/sasl"
)

func main() {
	// requests

	var req sasl.Request
	req.Login = "login"
	req.Password = "password"
	req.Service = ""
	req.Realm = "example.com"

	data, err := req.Marshal()
	if err != nil {
		fmt.Println("request encoding error:", err)
		return
	}
	fmt.Printf("Request encoded: %q\n", data)

	var req2 sasl.Request
	if err = req2.Unmarshal(data); err != nil {
		fmt.Println("request decoding error:", err)
		return
	}
	fmt.Printf("Request decoded: %+v\n", req2)

	// responses

	var resp sasl.Response
	resp.Result = false
	resp.Message = "invalid username/password"

	if data, err = resp.Marshal(); err != nil {
		fmt.Println("response encoding error:", err)
	}
	fmt.Printf("Response encoded: %q\n", data)

	var resp2 sasl.Response
	if err = resp2.Unmarshal(data); err != nil {
		fmt.Println("response decoding error:", err)
		return
	}
	fmt.Printf("Response decoded: %+v\n", resp2)

}
