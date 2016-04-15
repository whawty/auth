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
	"net"
	"os"
	"sort"
	"strconv"
	"sync"

	"github.com/codegangsta/cli"
	"github.com/coreos/go-systemd/activation"
	"github.com/gosuri/uitable"
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

func cmdInit(c *cli.Context) {
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

	s, err := NewStore(c.GlobalString("conf"), c.GlobalString("do-upgrades"))
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

func cmdCheck(c *cli.Context) {
	s, err := NewStore(c.GlobalString("conf"), c.GlobalString("do-upgrades"))
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

func openAndCheck(c *cli.Context) *Store {
	s, err := NewStore(c.GlobalString("conf"), c.GlobalString("do-upgrades"))
	if err != nil {
		fmt.Printf("Error opening whawty store: %s\n", err)
		return nil
	}

	if !c.GlobalBool("do-check") {
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

func cmdAdd(c *cli.Context) {
	s := openAndCheck(c)
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

func cmdRemove(c *cli.Context) {
	s := openAndCheck(c)
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

func cmdUpdate(c *cli.Context) {
	s := openAndCheck(c)
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

func cmdSetAdmin(c *cli.Context) {
	s := openAndCheck(c)
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
			fmt.Printf("user '%s' is now a normal user!\n", username)
		}
	}
}

func cmdListFull(s *StoreChan) {
	lst, err := s.ListFull()
	if err != nil {
		fmt.Printf("Error listing user: %s\n", err)
		return
	}

	var keys []string
	for k := range lst {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	table := uitable.New()
	table.MaxColWidth = 80
	table.AddRow("NAME", "TYPE", "LAST-CHANGED", "VALID", "SUPPORTED", "FORMAT", "PARAMS")
	for _, k := range keys {
		t := "user"
		if lst[k].IsAdmin {
			t = "admin"
		}
		table.AddRow(k, t, lst[k].LastChanged.String(), lst[k].IsValid, lst[k].IsSupported, lst[k].FormatID, lst[k].FormatParams)
	}
	fmt.Println(table)
}

func cmdListSupported(s *StoreChan) {
	lst, err := s.List()
	if err != nil {
		fmt.Printf("Error listing user: %s\n", err)
		return
	}

	var keys []string
	for k := range lst {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	table := uitable.New()
	table.MaxColWidth = 50
	table.AddRow("NAME", "TYPE", "LAST-CHANGED")
	for _, k := range keys {
		t := "user"
		if lst[k].IsAdmin {
			t = "admin"
		}
		table.AddRow(k, t, lst[k].LastChanged.String())
	}
	fmt.Println(table)
}

func cmdList(c *cli.Context) {
	s := openAndCheck(c)
	if s == nil {
		return
	}

	if c.Bool("full") {
		cmdListFull(s.GetInterface())
	} else {
		cmdListSupported(s.GetInterface())
	}
}

func cmdAuthenticate(c *cli.Context) {
	s := openAndCheck(c)
	if s == nil {
		return
	}

	username := c.Args().First()
	if username == "" {
		cli.ShowCommandHelp(c, "authenticate")
		return
	}

	password := c.Args().Get(1)
	if password == "" {
		fmt.Printf("password for '%s': ", username)
		pwd, err := gopass.GetPasswd()
		if err != nil {
			if err != gopass.ErrInterrupted {
				fmt.Println(err)
			}
			return
		}
		password = string(pwd)
	}

	ok, isAdmin, _, err := s.GetInterface().Authenticate(username, password)
	if err != nil {
		fmt.Printf("Error authenticating user '%s': %s\n", username, err)
		os.Exit(2)
	}
	if !ok {
		fmt.Printf("Error wrong password for user '%s'\n", username)
		os.Exit(1)
	}

	if isAdmin {
		fmt.Printf("user '%s' is an admin\n", username)
	} else {
		fmt.Printf("user '%s' is a normal user\n", username)
	}
	os.Exit(0)
}

func cmdRun(c *cli.Context) {
	s := openAndCheck(c)
	if s == nil {
		return
	}

	webAddr := c.String("web-addr")
	saslPaths := c.StringSlice("sock")

	var wg sync.WaitGroup
	if webAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runWebAddr(webAddr, s.GetInterface(), c.GlobalString("web-static-dir")); err != nil {
				fmt.Printf("warning running web interface failed: %s\n", err)
			}
		}()
	}
	for _, path := range saslPaths {
		p := path
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runSaslAuthSocket(p, s.GetInterface()); err != nil {
				fmt.Printf("warning running auth agent(%s) failed: %s\n", p, err)
			}
		}()
	}
	wg.Wait()
	fmt.Printf("shutting down since all auth sockets have closed\n")
}

func cmdRunSa(c *cli.Context) {
	s := openAndCheck(c)
	if s == nil {
		return
	}
	listeners, err := activation.Listeners(true)
	if err != nil {
		fmt.Printf("fetching socket listeners from systemd failed: %s\n", err)
		return
	}

	fmt.Printf("got %d sockets from systemd\n", len(listeners))
	if len(listeners) == 0 {
		return
	}

	var wg sync.WaitGroup
	for idx, listener := range listeners {
		switch listener.(type) {
		case *net.UnixListener:
			fmt.Printf("listener[%d]: is a UNIX socket (-> saslauthd)\n", idx)
			wg.Add(1)
			ln := listener.(*net.UnixListener)
			go func() {
				defer wg.Done()
				if err := runSaslAuthSocketListener(ln, s.GetInterface()); err != nil {
					fmt.Printf("warning running auth agent failed: %s\n", err)
				}
			}()
		case *net.TCPListener:
			fmt.Printf("listener[%d]: is a TCP socket (-> HTTP)\n", idx)
			wg.Add(1)
			ln := listener.(*net.TCPListener)
			go func() {
				defer wg.Done()
				if err := runWebListener(ln, s.GetInterface(), c.GlobalString("web-static-dir")); err != nil {
					fmt.Printf("error running web-api: %s", err)
				}
			}()
		default:
			fmt.Printf("listener[%d]: has type %T (ingnoring)\n", idx, listener)
		}
	}
	wg.Wait()
	fmt.Printf("shutting down since all auth sockets have closed\n")
}

func main() {
	app := cli.NewApp()
	app.Name = "whawty-auth"
	app.Version = "0.1"
	app.Usage = "manage whawty auth stores"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "conf",
			Value:  "/etc/whawty/auth.json",
			Usage:  "path to the configuration file",
			EnvVar: "WHAWTY_AUTH_CONFIG",
		},
		cli.BoolTFlag{
			Name:   "do-check",
			Usage:  "run check on base directory before executing command",
			EnvVar: "WHAWTY_AUTH_DO_CHECK",
		},
		cli.StringFlag{
			Name:   "web-static-dir",
			Value:  "/usr/share/whawty/auth-admin/",
			Usage:  "path to static files for the web API",
			EnvVar: "WHAWTY_AUTH_WEB_STATIC_DIR",
		},
		cli.StringFlag{
			Name:   "do-upgrades",
			Value:  "",
			Usage:  "enable local or remote upgrades for password hashes",
			EnvVar: "WHAWTY_AUTH_DO_UPGRADES",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:      "init",
			Usage:     "initialize a whawty auth store directory",
			ArgsUsage: "<adminname> [ <password> ]",
			Action:    cmdInit,
		},
		{
			Name:      "check",
			Usage:     "check a whawty auth store directory",
			ArgsUsage: "",
			Action:    cmdCheck,
		},
		{
			Name:      "add",
			Usage:     "add a user to the store",
			ArgsUsage: "<username> [ <password> ]",
			Action:    cmdAdd,
		},
		{
			Name:      "remove",
			Usage:     "remove a user from the store",
			ArgsUsage: "<username>",
			Action:    cmdRemove,
		},
		{
			Name:      "update",
			Usage:     "update a users password",
			ArgsUsage: "<username> [ <password> ]",
			Action:    cmdUpdate,
		},
		{
			Name:      "set-admin",
			Usage:     "set/clear admin flag of a user",
			ArgsUsage: "<username> (true|false)",
			Action:    cmdSetAdmin,
		},
		{
			Name:  "list",
			Usage: "list all users",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "full",
					Usage: "show full user list",
				},
			},
			Action: cmdList,
		},
		{
			Name:      "authenticate",
			Usage:     "check if username/password are valid",
			ArgsUsage: "<username> [ <password> ]",
			Action:    cmdAuthenticate,
		},
		{
			Name:  "run",
			Usage: "run the auth agent",
			Flags: []cli.Flag{
				cli.StringSliceFlag{
					Name:   "sock",
					Usage:  "path to saslauthd compatible unix socket interface",
					EnvVar: "WHAWTY_AUTH_SASL_SOCK",
				},
				cli.StringFlag{
					Name:   "web-addr",
					Usage:  "address to listen on for web API",
					EnvVar: "WHAWTY_AUTH_WEB_ADDR",
				},
			},
			Action: cmdRun,
		},
		{
			Name:   "runsa",
			Usage:  "run the auth agent (using systemd socket-activation)",
			Action: cmdRunSa,
		},
	}

	wdl.Printf("calling app.Run()")
	app.Run(os.Args)
}
