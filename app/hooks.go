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

package main

import (
	"time"
)

type HooksCaller struct {
	Notify  chan bool
	dir     string
	timeout time.Duration
	pending uint
}

func (h *HooksCaller) call() {
	// TODO: call all executables inside h.dir
	wdl.Printf("Hooks: not yet implemented!")
}

func (h *HooksCaller) run() {
	t := time.NewTimer(h.timeout)
	t.Stop()
	for {
		select {
		case <-t.C:
			if h.pending > 1 {
				h.call()
			}
			h.pending = 0
		case <-h.Notify:
			if h.pending == 0 {
				h.call()
				t.Reset(h.timeout)
			}
			h.pending++
		}
	}
}

func NewHooksCaller(hooksDir string) (h *HooksCaller, err error) {
	// TODO: check if hooksDir exists

	h = &HooksCaller{}
	h.Notify = make(chan bool, 32)
	h.dir = hooksDir
	h.timeout = 5 * time.Second // TODO: hardcoded value
	h.pending = 0
	go h.run()
	return
}
