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

type cfgScryptAuthCtx struct {
	HmacKeyBase64 string `yaml:"hmackey"`
	Cost          uint   `yaml:"cost"`
	R             int    `yaml:"r"`
	P             int    `yaml:"p"`
}

type cfgArgon2IDCtx struct {
	Time    uint32 `yaml:"time"`
	Memory  uint32 `yaml:"memory"`
	Threads uint8  `yaml:"threads"`
	Length  uint32 `yaml:"length"`
}

type cfgCtx struct {
	ID         uint              `yaml:"id"`
	Scryptauth *cfgScryptAuthCtx `yaml:"scryptauth"`
	Argon2ID   *cfgArgon2IDCtx   `yaml:"argon2id"`
}

type config struct {
	BaseDir          string   `yaml:"basedir"`
	DefaultContextID uint     `yaml:"defaultctx"`
	Contexts         []cfgCtx `yaml:"contexts"`
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

func scryptAuthContextFromConfig(id uint, conf *cfgScryptAuthCtx) (*scryptauth.Context, error) {
	hk, err := base64.StdEncoding.DecodeString(conf.HmacKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("Error: can't decode HMAC Key for context ID %d: %s", id, err)
	}
	if len(hk) != scryptauth.KeyLength {
		return nil, fmt.Errorf("Error: HMAC Key for context ID %d has invalid length %d != %d", id, scryptauth.KeyLength, len(hk))
	}

	ctx, err := scryptauth.New(conf.Cost, hk)
	if err != nil {
		return nil, err
	}
	if conf.R > 0 {
		ctx.R = conf.R
	}
	if conf.P > 0 {
		ctx.P = conf.P
	}
	return ctx, nil
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
	d.DefaultContextID = c.DefaultContextID

	for _, ctx := range c.Contexts {
		if ctx.ID == 0 {
			return fmt.Errorf("Error: context ID 0 is reserved")
		}

		n := 0
		if ctx.Scryptauth != nil {
			n += 1
			sactx, err := scryptAuthContextFromConfig(ctx.ID, ctx.Scryptauth)
			if err != nil {
				return err
			}
			d.Contexts[ctx.ID] = &ScryptAuthContext{sactx}
		}

		if ctx.Argon2ID != nil {
			n += 1
			d.Contexts[ctx.ID] = &Argon2IDContext{ctx.Argon2ID}
		}

		if n == 0 {
			return fmt.Errorf("Error: context ID %d uses unknown algorithm", ctx.ID)
		}
		if n > 1 {
			return fmt.Errorf("Error: context ID %d has more than one algorithm configured", ctx.ID)
		}
	}
	if c.DefaultContextID == 0 {
		if len(d.Contexts) != 0 {
			return fmt.Errorf("Error: no default context")
		}
	} else if _, exists := d.Contexts[c.DefaultContextID]; !exists {
		return fmt.Errorf("Error: invalid default context %d", c.DefaultContextID)
	}
	d.DefaultContextID = c.DefaultContextID

	return nil
}
