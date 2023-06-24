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
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type cfgParams struct {
	ID         uint              `yaml:"id"`
	Scryptauth *ScryptAuthParams `yaml:"scryptauth"`
	Argon2ID   *Argon2IDParams   `yaml:"argon2id"`
}

type config struct {
	BaseDir string      `yaml:"basedir"`
	Default uint        `yaml:"default"`
	Params  []cfgParams `yaml:"params"`
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

func (d *Dir) fromConfig(configfile string) error {
	c, err := readConfig(configfile)
	if err != nil {
		return err
	}
	if c.BaseDir == "" {
		return fmt.Errorf("Error: config file does not contain a base directory")
	}
	d.BaseDir = c.BaseDir
	d.Default = c.Default

	for _, params := range c.Params {
		if params.ID == 0 {
			return fmt.Errorf("Error: parameter-set 0 is reserved")
		}

		n := 0
		if params.Scryptauth != nil {
			n += 1
			if d.Params[params.ID], err = NewScryptAuthHasher(params.Scryptauth); err != nil {
				return err
			}
		}

		if params.Argon2ID != nil {
			n += 1
			if d.Params[params.ID], err = NewArgon2IDHasher(params.Argon2ID); err != nil {
				return err
			}
		}

		if n == 0 {
			return fmt.Errorf("Error: parameter-set %d uses unknown algorithm", params.ID)
		}
		if n > 1 {
			return fmt.Errorf("Error: parameter-set %d has more than one algorithm configured", params.ID)
		}
	}
	if c.Default == 0 {
		if len(d.Params) != 0 {
			return fmt.Errorf("Error: no default parameter-set")
		}
	} else if _, exists := d.Params[c.Default]; !exists {
		return fmt.Errorf("Error: invalid default parameter-set %d", c.Default)
	}
	d.Default = c.Default

	return nil
}
