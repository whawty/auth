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
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/whawty/auth/store"
)

type initResult struct {
	err error
}

type initRequest struct {
	username string
	password string
	response chan<- initResult
}

type checkResult struct {
	ok  bool
	err error
}

type checkRequest struct {
	response chan<- checkResult
}

type addResult struct {
	err error
}

type addRequest struct {
	username string
	password string
	isAdmin  bool
	response chan<- addResult
}

type removeResult struct {
	err error
}

type removeRequest struct {
	username string
	response chan<- removeResult
}

type updateResult struct {
	err error
}

type updateRequest struct {
	username string
	password string
	response chan<- updateResult
}

type setAdminResult struct {
	err error
}

type setAdminRequest struct {
	username string
	isAdmin  bool
	response chan<- setAdminResult
}

type listResult struct {
	list store.UserList
	err  error
}

type listRequest struct {
	response chan<- listResult
}

type listFullResult struct {
	list store.UserListFull
	err  error
}

type listFullRequest struct {
	response chan<- listFullResult
}

type authenticateResult struct {
	ok          bool
	isAdmin     bool
	upgradeable bool
	lastChanged time.Time
	err         error
}

type authenticateRequest struct {
	username string
	password string
	response chan<- authenticateResult
}

type Store struct {
	dir              *store.Dir
	policy           PolicyChecker
	initChan         chan initRequest
	checkChan        chan checkRequest
	addChan          chan addRequest
	removeChan       chan removeRequest
	updateChan       chan updateRequest
	setAdminChan     chan setAdminRequest
	listChan         chan listRequest
	listFullChan     chan listFullRequest
	authenticateChan chan authenticateRequest
	upgradeChan      chan updateRequest
}

func (s *Store) init(username, password string) (result initResult) {
	if ok, err := s.policy.Check(password, username); !ok || err != nil {
		if err != nil {
			result.err = err
		} else {
			result.err = errors.New("password policy checked failed")
		}
		return
	}
	result.err = s.dir.Init(username, password)
	return
}

func (s *Store) check() (result checkResult) {
	result.ok, result.err = s.dir.Check()
	return
}

func (s *Store) add(username, password string, isAdmin bool) (result addResult) {
	if ok, err := s.policy.Check(password, username); !ok || err != nil {
		if err != nil {
			result.err = err
		} else {
			result.err = errors.New("password policy checked failed")
		}
		return
	}
	result.err = s.dir.AddUser(username, password, isAdmin)
	return
}

func (s *Store) remove(username string) (result removeResult) {
	//	result.err = s.dir.RemoveUser(username)
	s.dir.RemoveUser(username)
	return
}

func (s *Store) update(username, password string) (result updateResult) {
	if ok, err := s.policy.Check(password, username); !ok || err != nil {
		if err != nil {
			result.err = err
		} else {
			result.err = errors.New("password policy checked failed")
		}
		return
	}
	result.err = s.dir.UpdateUser(username, password)
	return
}

func (s *Store) setAdmin(username string, isAdmin bool) (result setAdminResult) {
	result.err = s.dir.SetAdmin(username, isAdmin)
	return
}

func (s *Store) list() (result listResult) {
	result.list, result.err = s.dir.List()
	return
}

func (s *Store) listFull() (result listFullResult) {
	result.list, result.err = s.dir.ListFull()
	return
}

func (s *Store) authenticate(username, password string) (result authenticateResult, upgradeable bool) {
	result.ok, result.isAdmin, upgradeable, result.lastChanged, result.err = s.dir.Authenticate(username, password)
	return
}

func (s *Store) dispatchRequests() {
	for {
		select {
		case req := <-s.initChan:
			req.response <- s.init(req.username, req.password)
		case req := <-s.checkChan:
			req.response <- s.check()
		case req := <-s.addChan:
			req.response <- s.add(req.username, req.password, req.isAdmin)
		case req := <-s.removeChan:
			req.response <- s.remove(req.username)
		case req := <-s.updateChan:
			if req.response != nil {
				req.response <- s.update(req.username, req.password)
			} else {
				wdl.Printf("upgrade(local): upgrading '%s'", req.username)
				if resp := s.update(req.username, req.password); resp.err != nil {
					wl.Printf("upgrade(local): failed for '%s': %v", req.username, resp.err)
				} else {
					wdl.Printf("upgrade(local): successfully upgraded '%s'", req.username)
				}
			}
		case req := <-s.setAdminChan:
			req.response <- s.setAdmin(req.username, req.isAdmin)
		case req := <-s.listChan:
			req.response <- s.list()
		case req := <-s.listFullChan:
			req.response <- s.listFull()
		case req := <-s.authenticateChan:
			resp, upgradeable := s.authenticate(req.username, req.password)
			req.response <- resp
			if upgradeable && s.upgradeChan != nil {
				s.upgradeChan <- updateRequest{username: req.username, password: req.password}
			}
		}
	}
}

func remoteHTTPUpgrade(update updateRequest, remote string) {
	reqdata, err := json.Marshal(webUpdateRequest{Username: update.username, OldPassword: update.password})
	if err != nil {
		wl.Printf("upgrade(remote): error while encoding update request: %v", err)
		return
	}
	req, _ := http.NewRequest("POST", remote, bytes.NewReader(reqdata))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		wl.Printf("upgrade(remote): error sending update request: %v", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		wl.Printf("upgrade(remote): failed for '%s' with status: %s", update.username, resp.Status)
	} else {
		wdl.Printf("upgrade(remote): successfully upgraded '%s'", update.username)
	}
}

func remoteHTTPUpgrader(upgradeChan <-chan updateRequest, remote string) {
	sem := make(chan bool, 10) // TODO: hardcoded value
	for update := range upgradeChan {
		select {
		case sem <- true:
			wdl.Printf("upgrade(remote): upgrading '%s' via %s", update.username, remote)
			go func(update updateRequest, remote string) {
				defer func() { <-sem }()
				remoteHTTPUpgrade(update, remote)
			}(update, remote)
		default:
			wdl.Printf("upgrade(remote): ignoring upgrade request for '%s' due to rate-limiting", update.username)
		}
	}
}

func runRemoteUpgrader(remote string) (upgradeChan chan updateRequest, err error) {
	var r *url.URL
	if r, err = url.Parse(remote); err != nil {
		return
	}
	switch r.Scheme {
	case "http":
		fallthrough
	case "https":
		upgradeChan = make(chan updateRequest, 10)
		go remoteHTTPUpgrader(upgradeChan, remote)
	default:
		err = errors.New("unsupported hash-upgrade mode, must be either empty, 'local' or a http(s) url to the master")
	}
	return
}

// *********************************************************
// Public Interface

type StoreChan struct {
	initChan         chan<- initRequest
	checkChan        chan<- checkRequest
	addChan          chan<- addRequest
	removeChan       chan<- removeRequest
	updateChan       chan<- updateRequest
	setAdminChan     chan<- setAdminRequest
	listChan         chan<- listRequest
	listFullChan     chan<- listFullRequest
	authenticateChan chan<- authenticateRequest
}

func (s *StoreChan) Init(username, password string) error {
	resCh := make(chan initResult)
	req := initRequest{}
	req.username = username
	req.password = password
	req.response = resCh
	s.initChan <- req

	res := <-resCh
	return res.err
}

func (s *StoreChan) Check() (bool, error) {
	resCh := make(chan checkResult)
	req := checkRequest{}
	req.response = resCh
	s.checkChan <- req

	res := <-resCh
	return res.ok, res.err
}

func (s *StoreChan) Add(username, password string, isAdmin bool) error {
	resCh := make(chan addResult)
	req := addRequest{}
	req.username = username
	req.password = password
	req.isAdmin = isAdmin
	req.response = resCh
	s.addChan <- req

	res := <-resCh
	return res.err
}

func (s *StoreChan) Remove(username string) error {
	resCh := make(chan removeResult)
	req := removeRequest{}
	req.username = username
	req.response = resCh
	s.removeChan <- req

	res := <-resCh
	return res.err
}

func (s *StoreChan) Update(username, password string) error {
	resCh := make(chan updateResult)
	req := updateRequest{}
	req.username = username
	req.password = password
	req.response = resCh
	s.updateChan <- req

	res := <-resCh
	return res.err
}

func (s *StoreChan) SetAdmin(username string, isAdmin bool) error {
	resCh := make(chan setAdminResult)
	req := setAdminRequest{}
	req.username = username
	req.isAdmin = isAdmin
	req.response = resCh
	s.setAdminChan <- req

	res := <-resCh
	return res.err
}

func (s *StoreChan) List() (store.UserList, error) {
	resCh := make(chan listResult)
	req := listRequest{}
	req.response = resCh
	s.listChan <- req

	res := <-resCh
	return res.list, res.err
}

func (s *StoreChan) ListFull() (store.UserListFull, error) {
	resCh := make(chan listFullResult)
	req := listFullRequest{}
	req.response = resCh
	s.listFullChan <- req

	res := <-resCh
	return res.list, res.err
}

func (s *StoreChan) Authenticate(username, password string) (bool, bool, time.Time, error) {
	resCh := make(chan authenticateResult)
	req := authenticateRequest{}
	req.username = username
	req.password = password
	req.response = resCh
	s.authenticateChan <- req

	res := <-resCh
	return res.ok, res.isAdmin, res.lastChanged, res.err
}

func (s *Store) GetInterface() *StoreChan {
	ch := &StoreChan{}
	ch.initChan = s.initChan
	ch.checkChan = s.checkChan
	ch.addChan = s.addChan
	ch.removeChan = s.removeChan
	ch.updateChan = s.updateChan
	ch.setAdminChan = s.setAdminChan
	ch.listChan = s.listChan
	ch.listFullChan = s.listFullChan
	ch.authenticateChan = s.authenticateChan
	return ch
}

func NewStore(configfile, doUpgrades, policyType, policyCondition string) (s *Store, err error) {
	s = &Store{}
	if s.dir, err = store.NewDirFromConfig(configfile); err != nil {
		return
	}
	if policyType != "" {
		if s.policy, err = NewPasswordPolicy(policyType, policyCondition); err != nil {
			return
		}
	}
	s.initChan = make(chan initRequest, 1)
	s.checkChan = make(chan checkRequest, 1)
	s.addChan = make(chan addRequest, 10)
	s.removeChan = make(chan removeRequest, 10)
	s.updateChan = make(chan updateRequest, 10)
	s.setAdminChan = make(chan setAdminRequest, 10)
	s.listChan = make(chan listRequest, 10)
	s.listFullChan = make(chan listFullRequest, 10)
	s.authenticateChan = make(chan authenticateRequest, 10)

	switch doUpgrades {
	case "":
		s.upgradeChan = nil
	case "local":
		s.upgradeChan = s.updateChan
	default:
		if s.upgradeChan, err = runRemoteUpgrader(doUpgrades); err != nil {
			return
		}
	}

	go s.dispatchRequests()
	return
}
