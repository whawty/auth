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

package store

import (
	"encoding/base64"
	"fmt"
	"os"

	"gopkg.in/spreadspace/scryptauth.v2"
	"gopkg.in/yaml.v3"
)

type cfgScryptauthCtx struct {
	HmacKeyBase64 string `yaml:"hmackey"`
	Cost          uint   `yaml:"cost"`
	R             int    `yaml:"r"`
	P             int    `yaml:"p"`
}

// type cfgArgonIDCtx struct {
// 	Time    uint32 `yaml:"time"`
// 	Memory  uint32 `yaml:"memory"`
// 	Threads uint8  `yaml:"threads"`
// }

type cfgCtx struct {
	ID         uint              `yaml:"id"`
	Scryptauth *cfgScryptauthCtx `yaml:"scryptauth"`
	//	ArgonID    *cfgArgonIDCtx `yaml:"argonid"`
}

type config struct {
	BaseDir    string   `yaml:"basedir"`
	DefaultCtx uint     `yaml:"defaultctx"`
	Contexts   []cfgCtx `yaml:"contexts"`
}

func readConfig(configfile string) (*config, error) {
	file, err := os.Open(configfile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)

	c := &config{}
	if err = decoder.Decode(c); err != nil {
		return nil, fmt.Errorf("Error parsing config file: %s", err)
	}
	return c, nil
}

func scryptauthContextFromConfig(id uint, ctx *cfgScryptauthCtx) (*scryptauth.Context, error) {
	hk, err := base64.StdEncoding.DecodeString(ctx.HmacKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("Error: can't decode HMAC Key for context ID %d: %s", id, err)
	}
	if len(hk) != scryptauth.KeyLength {
		return nil, fmt.Errorf("Error: HMAC Key for context ID %d has invalid length %d != %d", id, scryptauth.KeyLength, len(hk))
	}

	sactx, err := scryptauth.New(ctx.Cost, hk)
	if err != nil {
		return nil, err
	}
	if ctx.R > 0 {
		sactx.R = ctx.R
	}
	if ctx.P > 0 {
		sactx.P = ctx.P
	}
	return sactx, nil
}

func (d *Dir) fromConfig(configfile string) error {
	c, err := readConfig(configfile)
	if err != nil {
		return err
	}
	if c.BaseDir == "" {
		return fmt.Errorf("Error: config file does not contain a base directory")
	}
	d.BaseDir = c.BaseDir

	// Format: scryptauth
	for _, ctx := range c.Contexts {
		if ctx.ID == 0 {
			return fmt.Errorf("Error: context ID 0 is reserved")
		}

		if ctx.Scryptauth != nil {
			// TODO: error if
			sactx, err := scryptauthContextFromConfig(ctx.ID, ctx.Scryptauth)
			if err != nil {
				return err
			}
			d.Scryptauth.Contexts[ctx.ID] = sactx
		} else {
			return fmt.Errorf("Error: context ID %d uses unknown algorithm", ctx.ID)
		}
	}
	if c.DefaultCtx == 0 {
		if len(d.Scryptauth.Contexts) != 0 {
			return fmt.Errorf("Error: no default context")
		}
	} else if _, exists := d.Scryptauth.Contexts[c.DefaultCtx]; !exists {
		return fmt.Errorf("Error: invalid default context %d", c.DefaultCtx)
	}
	d.Scryptauth.DefaultCtxID = c.DefaultCtx

	return nil
}
