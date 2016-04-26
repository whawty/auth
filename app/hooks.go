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
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type HooksCaller struct {
	Notify    chan bool
	dir       string
	store     string
	rateLimit time.Duration
	pending   uint
}

func runHook(executeable, store string) {
	wdl.Printf("Hooks: calling '%s'", executeable)

	cmd := exec.Command(executeable, "update")
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	cmd.Env = append(os.Environ(), fmt.Sprintf("WHAWTY_AUTH_STORE=%s", store))

	if err := cmd.Start(); err != nil {
		wl.Printf("Hooks: error calling '%s': %v", executeable, err)
		return
	}

	go func() {
		exited := make(chan error)
		go func() {
			exited <- cmd.Wait()
		}()

		t := time.NewTimer(time.Minute) // TODO: hardcoded value
		defer t.Stop()

		for {
			select {
			case <-t.C:
				wl.Printf("Hooks: killing long running hook '%s'", executeable)
				cmd.Process.Kill()
			case err := <-exited:
				if err != nil {
					wl.Printf("Hooks: '%s': %v", executeable, err)
				} else {
					wdl.Printf("Hooks: '%s': %s", executeable, cmd.ProcessState)
				}
				return
			}
		}
	}()
}

func (h *HooksCaller) runAllHooks() {
	dir, err := os.Open(h.dir)
	if err != nil {
		wl.Printf("Hooks: error opening hooks directory: %v", err)
		return
	}
	defer dir.Close()

	var dirInfo os.FileInfo
	if dirInfo, err = dir.Stat(); err != nil {
		wl.Printf("Hooks: error opening hooks directory: %v", err)
		return
	}

	if !dirInfo.IsDir() {
		wl.Printf("Hooks: '%s' is not a directory", h.dir)
		return
	}
	if dirInfo.Mode()&02 != 0 {
		wl.Printf("Hooks: '%s' is world-writable - won't call any hook scripts from here", h.dir)
		return
	}

	var files []os.FileInfo
	if files, err = dir.Readdir(0); err != nil {
		wl.Printf("Hooks: error reading hooks directory: %v", err)
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name(), ".") { // hidden files
			continue
		}

		m := file.Mode()
		if !m.IsRegular() && (m&os.ModeSymlink) == 0 { // no special files except symlinks
			continue
		}

		if m&0111 == 0 { // not executeable -> we still don't know if we are allowed to execute it...
			continue
		}

		runHook(filepath.Join(h.dir, path.Clean("/"+file.Name())), h.store)
	}
}

func (h *HooksCaller) run() {
	if h.dir == "" { // just consume requests and do nothing
		for {
			<-h.Notify
		}
	}

	t := time.NewTimer(h.rateLimit)
	t.Stop()
	for {
		select {
		case <-t.C:
			if h.pending > 1 {
				h.runAllHooks()
			}
			h.pending = 0
		case <-h.Notify:
			if h.pending == 0 {
				h.runAllHooks()
				t.Reset(h.rateLimit)
			}
			h.pending++
		}
	}
}

func NewHooksCaller(hooksDir, storeDir string) (h *HooksCaller, err error) {
	if hooksDir != "" {
		var d os.FileInfo
		if d, err = os.Stat(hooksDir); err != nil {
			return
		}
		if !d.IsDir() {
			return nil, fmt.Errorf("Hooks: '%s' is not a directory", hooksDir)
		}
	}

	h = &HooksCaller{}
	h.Notify = make(chan bool, 32)
	h.dir = hooksDir
	h.store = storeDir
	h.rateLimit = 5 * time.Second // TODO: hardcoded value
	h.pending = 0
	go h.run()
	return
}
