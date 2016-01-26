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
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"github.com/codegangsta/cli"
	"github.com/howeyc/gopass"
)

var (
	wl  = log.New(os.Stdout, "[whawty.auth]\t", log.LstdFlags)
	wdl = log.New(ioutil.Discard, "[whawty.auth dbg]\t", log.LstdFlags)
)

func init() {
	if _, exists := os.LookupEnv("WHAWTY_AUTH_DEBUG"); exists {
		wdl.SetOutput(os.Stderr)
	}
}

func askPass() (string, error) {
	fmt.Printf("new password: ")
	if p1, err := gopass.GetPasswd(); err != nil || len(p1) == 0 {
		return "", err
	} else {
		fmt.Printf("retype password: ")
		if p2, err := gopass.GetPasswd(); err != nil || len(p2) == 0 {
			return "", err
		} else {
			if string(p1) == string(p2) {
				return string(p1), nil
			} else {
				return "", fmt.Errorf("passwords don't match!")
			}
		}
	}
}

func cmdInit(configfile string, c *cli.Context) {
	username := c.Args().First()
	if username == "" {
		cli.ShowCommandHelp(c, "init")
		return
	}

	password := c.Args().Get(1)
	if password == "" {
		pwd, err := askPass()
		if err != nil {
			if err != gopass.ErrInterrupted {
				fmt.Println(err)
			}
			return
		}
		password = pwd
	}

	s, err := NewStore(configfile)
	if err != nil {
		fmt.Printf("Error initializing whawty store: %s\n", err)
		return
	}
	if err := s.GetInterface().Init(username, password); err != nil {
		fmt.Printf("Error initializing whawty store: %s\n", err)
		return
	}
	fmt.Printf("whawty store successfully initialized!\n")
}

func cmdCheck(configfile string, c *cli.Context) {
	s, err := NewStore(configfile)
	if err != nil {
		fmt.Printf("Error opening whawty store: %s\n", err)
		return
	}
	if ok, err := s.GetInterface().Check(); err != nil {
		fmt.Printf("Error checking whawty store: %s\n", err)
		return
	} else {
		if ok {
			fmt.Printf("whawty store is ok!\n")
			os.Exit(0)
		} else {
			fmt.Printf("whawty store is invalid!\n")
			os.Exit(1)
		}
	}
}

func openAndCheck(configfile string, docheck bool) *Store {
	s, err := NewStore(configfile)
	if err != nil {
		fmt.Printf("Error opening whawty store: %s\n", err)
		return nil
	}

	if !docheck {
		return s
	}

	if ok, err := s.GetInterface().Check(); err != nil {
		fmt.Printf("Error checking whawty store: %s\n", err)
		return nil
	} else if !ok {
		fmt.Printf("Error whawty store is invalid!\n")
		return nil
	}
	return s
}

func cmdAdd(configfile string, docheck bool, c *cli.Context) {
	s := openAndCheck(configfile, docheck)
	if s == nil {
		return
	}

	username := c.Args().First()
	if username == "" {
		cli.ShowCommandHelp(c, "add")
		return
	}

	password := c.Args().Get(1)
	if password == "" {
		pwd, err := askPass()
		if err != nil {
			if err != gopass.ErrInterrupted {
				fmt.Println(err)
			}
			return
		}
		password = pwd
	}

	if err := s.GetInterface().Add(username, password, false); err != nil {
		fmt.Printf("Error adding user '%s': %s\n", username, err)
	} else {
		fmt.Printf("user '%s' successfully added!\n", username)
	}
}

func cmdRemove(configfile string, docheck bool, c *cli.Context) {
	s := openAndCheck(configfile, docheck)
	if s == nil {
		return
	}

	username := c.Args().First()
	if username == "" {
		cli.ShowCommandHelp(c, "remove")
		return
	}

	if err := s.GetInterface().Remove(username); err != nil {
		fmt.Printf("Error removing user '%s': %s\n", username, err)
	} else {
		fmt.Printf("user '%s' successfully removed!\n", username)
	}
}

func cmdUpdate(configfile string, docheck bool, c *cli.Context) {
	s := openAndCheck(configfile, docheck)
	if s == nil {
		return
	}

	username := c.Args().First()
	if username == "" {
		cli.ShowCommandHelp(c, "update")
		return
	}

	password := c.Args().Get(1)
	if password == "" {
		pwd, err := askPass()
		if err != nil {
			if err != gopass.ErrInterrupted {
				fmt.Println(err)
			}
			return
		}
		password = pwd
	}

	if err := s.GetInterface().Update(username, password); err != nil {
		fmt.Printf("Error updating user '%s': %s\n", username, err)
	} else {
		fmt.Printf("user '%s' successfully updated!\n", username)
	}
}

func cmdSetAdmin(configfile string, docheck bool, c *cli.Context) {
	s := openAndCheck(configfile, docheck)
	if s == nil {
		return
	}

	username := c.Args().First()
	if username == "" {
		cli.ShowCommandHelp(c, "set-admin")
		return
	}

	isAdmin, err := strconv.ParseBool(c.Args().Get(1))
	if err != nil {
		cli.ShowCommandHelp(c, "set-admin")
		return
	}

	if err := s.GetInterface().SetAdmin(username, isAdmin); err != nil {
		fmt.Printf("Error changing admin status of user '%s': %s\n", username, err)
	} else {
		if isAdmin {
			fmt.Printf("user '%s' is now an admin!\n", username)
		} else {
			fmt.Printf("user '%s' is now n normal user!\n", username)
		}
	}
}

func main() {
	var configfile string
	var docheck bool

	app := cli.NewApp()
	app.Name = "whawty-auth"
	app.Version = "0.1"
	app.Usage = "manage whawty auth stores"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "conf, c",
			Value:       "/etc/whawty-auth/default.json",
			Usage:       "base directory of the whawty auth store",
			Destination: &configfile,
			EnvVar:      "WHAWTY_AUTH_CONFIG",
		},
		cli.BoolTFlag{
			Name:        "do-check",
			Usage:       "run check on base directory before executing command",
			Destination: &docheck,
			EnvVar:      "WHAWTY_AUTH_DO_CHECK",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:      "init",
			Usage:     "initialize a whawty auth store directory",
			ArgsUsage: "<adminname> [ <password> ]",
			Action: func(c *cli.Context) {
				cmdInit(configfile, c)
			},
		},
		{
			Name:      "check",
			Usage:     "check a whawty auth store directory",
			ArgsUsage: "",
			Action: func(c *cli.Context) {
				cmdCheck(configfile, c)
			},
		},
		{
			Name:      "add",
			Usage:     "add a user to the store",
			ArgsUsage: "<username> [ <password> ]",
			Action: func(c *cli.Context) {
				cmdAdd(configfile, docheck, c)
			},
		},
		{
			Name:      "remove",
			Usage:     "remove a user from the store",
			ArgsUsage: "<username>",
			Action: func(c *cli.Context) {
				cmdRemove(configfile, docheck, c)
			},
		},
		{
			Name:      "update",
			Usage:     "update a users password",
			ArgsUsage: "<username> [ <password> ]",
			Action: func(c *cli.Context) {
				cmdUpdate(configfile, docheck, c)
			},
		},
		{
			Name:      "set-admin",
			Usage:     "set/clear admin flag of a user",
			ArgsUsage: "<username> (true|false)",
			Action: func(c *cli.Context) {
				cmdSetAdmin(configfile, docheck, c)
			},
		},
	}

	app.Run(os.Args)
}
