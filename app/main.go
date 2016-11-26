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
	"io/ioutil"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

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
		if len(p1) == 0 {
			return "", fmt.Errorf("empyty password is not allowed!")
		}
		return "", err
	} else {
		fmt.Printf("retype password: ")
		if p2, err := gopass.GetPasswd(); err != nil {
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

func cmdInit(c *cli.Context) error {
	username := c.Args().First()
	if username == "" {
		cli.ShowCommandHelp(c, "init")
		return cli.NewExitError("", 0)
	}

	password := c.Args().Get(1)
	if password == "" {
		pwd, err := askPass()
		if err != nil {
			if err != gopass.ErrInterrupted {
				return cli.NewExitError(err.Error(), 2)
			}
			return cli.NewExitError("", 2)
		}
		password = pwd
	}

	s, err := NewStore(c.GlobalString("store"), c.GlobalString("do-upgrades"),
		c.GlobalString("policy-type"), c.GlobalString("policy-condition"), c.GlobalString("hooks-dir"))
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Error initializing whawty store: %s", err), 3)
	}
	if err := s.GetInterface().Init(username, password); err != nil {
		return cli.NewExitError(fmt.Sprintf("Error initializing whawty store: %s", err), 3)
	}
	return cli.NewExitError(fmt.Sprintf("whawty store successfully initialized!"), 0)
}

func cmdCheck(c *cli.Context) error {
	s, err := NewStore(c.GlobalString("store"), c.GlobalString("do-upgrades"),
		c.GlobalString("policy-type"), c.GlobalString("policy-condition"), c.GlobalString("hooks-dir"))
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Error opening whawty store: %s", err), 3)
	}
	ok, err := s.GetInterface().Check()
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Error checking whawty store: %s", err), 3)
	}
	if !ok {
		return cli.NewExitError(fmt.Sprintf("whawty store is invalid!"), 1)
	}
	return cli.NewExitError(fmt.Sprintf("whawty store is ok!"), 0)
}

func openAndCheck(c *cli.Context) (*Store, error) {
	s, err := NewStore(c.GlobalString("store"), c.GlobalString("do-upgrades"),
		c.GlobalString("policy-type"), c.GlobalString("policy-condition"), c.GlobalString("hooks-dir"))
	if err != nil {
		return nil, fmt.Errorf("Error opening whawty store: %s", err)
	}

	if !c.GlobalBool("do-check") {
		return s, nil
	}

	if ok, err := s.GetInterface().Check(); err != nil {
		return nil, fmt.Errorf("Error checking whawty store: %s", err)
	} else if !ok {
		return nil, fmt.Errorf("Error whawty store is invalid!")
	}
	return s, nil
}

func cmdAdd(c *cli.Context) error {
	s, err := openAndCheck(c)
	if err != nil {
		return cli.NewExitError(err.Error(), 3)
	}

	username := c.Args().First()
	if username == "" {
		cli.ShowCommandHelp(c, "add")
		return cli.NewExitError("", 0)
	}

	password := c.Args().Get(1)
	if password == "" {
		pwd, err := askPass()
		if err != nil {
			if err != gopass.ErrInterrupted {
				return cli.NewExitError(err.Error(), 2)
			}
			return cli.NewExitError("", 2)
		}
		password = pwd
	}

	if err := s.GetInterface().Add(username, password, false); err != nil {
		return cli.NewExitError(fmt.Sprintf("Error adding user '%s': %s", username, err), 3)
	}
	return cli.NewExitError(fmt.Sprintf("user '%s' successfully added!", username), 0)
}

func cmdRemove(c *cli.Context) error {
	s, err := openAndCheck(c)
	if err != nil {
		return cli.NewExitError(err.Error(), 3)
	}

	username := c.Args().First()
	if username == "" {
		cli.ShowCommandHelp(c, "remove")
		return cli.NewExitError("", 0)
	}

	if err := s.GetInterface().Remove(username); err != nil {
		return cli.NewExitError(fmt.Sprintf("Error removing user '%s': %s", username, err), 3)
	}
	return cli.NewExitError(fmt.Sprintf("user '%s' successfully removed!", username), 0)
}

func cmdUpdate(c *cli.Context) error {
	s, err := openAndCheck(c)
	if err != nil {
		return cli.NewExitError(err.Error(), 3)
	}

	username := c.Args().First()
	if username == "" {
		cli.ShowCommandHelp(c, "update")
		return cli.NewExitError("", 0)
	}

	password := c.Args().Get(1)
	if password == "" {
		pwd, err := askPass()
		if err != nil {
			if err != gopass.ErrInterrupted {
				return cli.NewExitError(err.Error(), 2)
			}
			return cli.NewExitError("", 2)
		}
		password = pwd
	}

	if err := s.GetInterface().Update(username, password); err != nil {
		return cli.NewExitError(fmt.Sprintf("Error updating user '%s': %s", username, err), 3)
	}
	return cli.NewExitError(fmt.Sprintf("user '%s' successfully updated!", username), 0)
}

func cmdSetAdmin(c *cli.Context) error {
	s, err := openAndCheck(c)
	if err != nil {
		return cli.NewExitError(err.Error(), 3)
	}

	username := c.Args().First()
	if username == "" {
		cli.ShowCommandHelp(c, "set-admin")
		return cli.NewExitError("", 0)
	}

	isAdmin, err := strconv.ParseBool(c.Args().Get(1))
	if err != nil {
		cli.ShowCommandHelp(c, "set-admin")
		return cli.NewExitError("", 0)
	}

	if err := s.GetInterface().SetAdmin(username, isAdmin); err != nil {
		return cli.NewExitError(fmt.Sprintf("Error changing admin status of user '%s': %s", username, err), 3)
	}

	if isAdmin {
		return cli.NewExitError(fmt.Sprintf("user '%s' is now an admin!", username), 0)
	} else {
		return cli.NewExitError(fmt.Sprintf("user '%s' is now a normal user!", username), 0)
	}
}

func cmdListFull(s *StoreChan) error {
	lst, err := s.ListFull()
	if err != nil {
		return fmt.Errorf("Error listing user: %s\n", err)
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
	return nil
}

func cmdListSupported(s *StoreChan) error {
	lst, err := s.List()
	if err != nil {
		return fmt.Errorf("Error listing user: %s\n", err)
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
	return nil
}

func cmdList(c *cli.Context) error {
	s, err := openAndCheck(c)
	if err != nil {
		return cli.NewExitError(err.Error(), 3)
	}

	if c.Bool("full") {
		err = cmdListFull(s.GetInterface())
	} else {
		err = cmdListSupported(s.GetInterface())
	}
	if err != nil {
		return cli.NewExitError(err.Error(), 3)
	}
	return cli.NewExitError("", 0)
}

func cmdAuthenticate(c *cli.Context) error {
	s, err := openAndCheck(c)
	if err != nil {
		return cli.NewExitError(err.Error(), 3)
	}

	username := c.Args().First()
	if username == "" {
		cli.ShowCommandHelp(c, "authenticate")
		return cli.NewExitError("", 0)
	}

	password := c.Args().Get(1)
	if password == "" {
		fmt.Printf("password for '%s': ", username)
		pwd, err := gopass.GetPasswd()
		if err != nil {
			if err != gopass.ErrInterrupted {
				return cli.NewExitError(err.Error(), 2)
			}
			return cli.NewExitError("", 2)
		}
		password = string(pwd)
	}

	ok, isAdmin, _, err := s.GetInterface().Authenticate(username, password)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Error authenticating user '%s': %s", username, err), 3)
	}
	if !ok {
		return cli.NewExitError(fmt.Sprintf("Error wrong password for user '%s'", username), 1)
	}

	// wait for potential upgrades - this might still be to fast for remote upgrades
	// TODO: find a better way to handle this situation
	time.Sleep(100 * time.Millisecond)

	if isAdmin {
		return cli.NewExitError(fmt.Sprintf("user '%s' is an admin.", username), 0)
	} else {
		return cli.NewExitError(fmt.Sprintf("user '%s' is a normal user.", username), 0)
	}
}

func cmdRun(c *cli.Context) error {
	s, err := openAndCheck(c)
	if err != nil {
		return cli.NewExitError(err.Error(), 3)
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

	return cli.NewExitError(fmt.Sprintf("shutting down since all auth sockets have closed."), 0)
}

func cmdRunSa(c *cli.Context) error {
	s, err := openAndCheck(c)
	if err != nil {
		return cli.NewExitError(err.Error(), 3)
	}

	listeners, err := activation.Listeners(true)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("fetching socket listeners from systemd failed: %s", err), 2)
	}

	fmt.Printf("got %d sockets from systemd\n", len(listeners))
	if len(listeners) == 0 {
		return cli.NewExitError("shutting down since there are no sockets to lissten on.", 2)
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

	return cli.NewExitError(fmt.Sprintf("shutting down since all auth sockets have closed."), 0)
}

func main() {
	app := cli.NewApp()
	app.Name = "whawty-auth"
	app.Version = "0.1-rc2"
	app.Usage = "manage whawty auth stores"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "store",
			Value:  "/etc/whawty/auth-store.json",
			Usage:  "path to the store configuration file",
			EnvVar: "WHAWTY_AUTH_STORE_CONFIG",
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
		cli.StringFlag{
			Name:   "policy-type",
			Value:  "",
			Usage:  "password policy type",
			EnvVar: "WHAWTY_AUTH_POLICY_TYPE",
		},
		cli.StringFlag{
			Name:   "policy-condition",
			Value:  "",
			Usage:  "password policy condition",
			EnvVar: "WHAWTY_AUTH_POLICY_CONDITION",
		},
		cli.StringFlag{
			Name:   "hooks-dir",
			Value:  "",
			Usage:  "path to update hooks",
			EnvVar: "WHAWTY_AUTH_HOOKS_DIR",
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
