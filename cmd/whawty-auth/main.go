//
// Copyright (c) 2016-2019 whawty contributors (see AUTHORS file)
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

	"github.com/coreos/go-systemd/activation"
	"github.com/gosuri/uitable"
	"github.com/howeyc/gopass"
	"github.com/urfave/cli"
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
		cli.ShowCommandHelp(c, "init") //nolint:errcheck
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

	if err := s.GetInterface().Check(); err != nil {
		return cli.NewExitError(fmt.Sprintf("Error checking whawty store: %s", err), 3)
	}
	return cli.NewExitError(fmt.Sprintf("whawty store is ok!"), 0)
}

func openAndCheck(c *cli.Context) (*store, error) {
	s, err := NewStore(c.GlobalString("store"), c.GlobalString("do-upgrades"),
		c.GlobalString("policy-type"), c.GlobalString("policy-condition"), c.GlobalString("hooks-dir"))
	if err != nil {
		return nil, fmt.Errorf("Error opening whawty store: %s", err)
	}

	if !c.GlobalBool("do-check") {
		return s, nil
	}

	if err := s.GetInterface().Check(); err != nil {
		return nil, fmt.Errorf("Error checking whawty store: %s", err)
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
		cli.ShowCommandHelp(c, "add") //nolint:errcheck
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
		cli.ShowCommandHelp(c, "remove") //nolint:errcheck
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
		cli.ShowCommandHelp(c, "update") //nolint:errcheck
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
		cli.ShowCommandHelp(c, "set-admin") //nolint:errcheck
		return cli.NewExitError("", 0)
	}

	isAdmin, err := strconv.ParseBool(c.Args().Get(1))
	if err != nil {
		cli.ShowCommandHelp(c, "set-admin") //nolint:errcheck
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

func cmdListFull(s *Store) error {
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
	table.AddRow("NAME", "TYPE", "LAST-CHANGED", "VALID", "SUPPORTED", "FORMAT", "PARAMETER-SET")
	for _, k := range keys {
		t := "user"
		if lst[k].IsAdmin {
			t = "admin"
		}
		table.AddRow(k, t, lst[k].LastChanged.String(), lst[k].IsValid, lst[k].IsSupported, lst[k].FormatID, lst[k].ParamID)
	}
	fmt.Println(table)
	return nil
}

func cmdListSupported(s *Store) error {
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
		cli.ShowCommandHelp(c, "authenticate") //nolint:errcheck
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

	// wait for potential upgrades - this might still be too fast for remote upgrades
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

	var lc *listenerConfig
	if c.String("listener") != "" {
		lc, err = readListenerConfig(c.String("listener"))
		if err != nil {
			return cli.NewExitError(err.Error(), 1)
		}
	}

	var wg sync.WaitGroup
	if lc.SASLAuthd != nil {
		for _, path := range lc.SASLAuthd.Listen {
			p := path
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := runSaslAuthSocket(p, s.GetInterface()); err != nil {
					fmt.Printf("warning running auth-socket failed: %s\n", err)
				}
			}()
		}
	}
	if lc.HTTP != nil {
		for _, addr := range lc.HTTP.Listen {
			a := addr
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := runHTTPAddr(a, lc.HTTP, s.GetInterface()); err != nil {
					fmt.Printf("warning running web-api failed: %s\n", err)
				}
			}()
		}
	}
	if lc.HTTPs != nil {
		for _, addr := range lc.HTTPs.Listen {
			a := addr
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := runHTTPsAddr(a, lc.HTTPs, s.GetInterface()); err != nil {
					fmt.Printf("warning running web-api failed: %s\n", err)
				}
			}()
		}
	}
	if lc.LDAP != nil {
		for _, addr := range lc.LDAP.Listen {
			a := addr
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := runLDAPAddr(a, lc.LDAP, s.GetInterface()); err != nil {
					fmt.Printf("warning running web-api failed: %s\n", err)
				}
			}()
		}
	}
	if lc.LDAPs != nil {
		for _, addr := range lc.LDAPs.Listen {
			a := addr
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := runLDAPsAddr(a, lc.LDAPs, s.GetInterface()); err != nil {
					fmt.Printf("warning running web-api failed: %s\n", err)
				}
			}()
		}
	}
	wg.Wait()

	return cli.NewExitError(fmt.Sprintf("shutting down since all auth sockets have closed."), 0)
}

func cmdRunSa(c *cli.Context) error {
	s, err := openAndCheck(c)
	if err != nil {
		return cli.NewExitError(err.Error(), 3)
	}

	var lc *listenerConfig
	if c.String("listener") != "" {
		lc, err = readListenerConfig(c.String("listener"))
		if err != nil {
			return cli.NewExitError(err.Error(), 1)
		}
	}

	listenerGroups, err := activation.ListenersWithNames()
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("fetching socket listeners from systemd failed: %s", err), 2)
	}

	fmt.Printf("got %d listener-groups from systemd\n", len(listenerGroups))
	if len(listenerGroups) == 0 {
		return cli.NewExitError("shutting down since there are no sockets to lissten on.", 2)
	}

	var wg sync.WaitGroup
	for name, listeners := range listenerGroups {
		switch name {
		case "saslauthd":
			if lc.SASLAuthd == nil {
				fmt.Printf("ingoring unexpected socket for saslauthd-compatible listener (no config found in listener-config)\n")
				continue
			}
			for _, listener := range listeners {
				ln, ok := listener.(*net.UnixListener)
				if !ok {
					fmt.Printf("ingoring invalid socket type %T for saslauthd-compatible listener\n", listener)
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := runSaslAuthSocketListener(ln, s.GetInterface()); err != nil {
						fmt.Printf("warning running auth-socket failed: %s\n", err)
					}
				}()
			}
		case "http":
			if lc.HTTP == nil {
				fmt.Printf("ingoring unexpected socket for HTTP listener (no config found in listener-config)\n")
				continue
			}
			for _, listener := range listeners {
				ln, ok := listener.(*net.TCPListener)
				if !ok {
					fmt.Printf("ingoring invalid socket type %T for HTTP listener\n", listener)
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := runHTTPListener(ln, lc.HTTP, s.GetInterface()); err != nil {
						fmt.Printf("warning running web-api failed: %s\n", err)
					}
				}()
			}
		case "https":
			if lc.HTTPs == nil {
				fmt.Printf("ingoring unexpected socket for HTTPs listener (no config found in listener-config)\n")
				continue
			}
			for _, listener := range listeners {
				ln, ok := listener.(*net.TCPListener)
				if !ok {
					fmt.Printf("ingoring invalid socket type %T for HTTPs listener\n", listener)
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := runHTTPsListener(ln, lc.HTTPs, s.GetInterface()); err != nil {
						fmt.Printf("warning running web-api failed: %s\n", err)
					}
				}()
			}
		case "ldap":
			if lc.LDAP == nil {
				fmt.Printf("ingoring unexpected socket for LDAP listener (no config found in listener-config)\n")
				continue
			}
			for _, listener := range listeners {
				ln, ok := listener.(*net.TCPListener)
				if !ok {
					fmt.Printf("ingoring invalid socket type %T for LDAP listener\n", listener)
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := runLDAPListener(ln, lc.LDAP, s.GetInterface()); err != nil {
						fmt.Printf("warning running web-api failed: %s\n", err)
					}
				}()
			}
		case "ldaps":
			if lc.LDAPs == nil {
				fmt.Printf("ingoring unexpected socket for LDAPs listener (no config found in listener-config)\n")
				continue
			}
			for _, listener := range listeners {
				ln, ok := listener.(*net.TCPListener)
				if !ok {
					fmt.Printf("ingoring invalid socket type %T for LDAPs listener\n", listener)
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := runLDAPsListener(ln, lc.LDAPs, s.GetInterface()); err != nil {
						fmt.Printf("warning running web-api failed: %s\n", err)
					}
				}()
			}
		}

	}
	wg.Wait()

	return cli.NewExitError(fmt.Sprintf("shutting down since all auth sockets have closed."), 0)
}

func main() {
	app := cli.NewApp()
	app.Name = "whawty-auth"
	app.Version = "0.2"
	app.Usage = "manage whawty auth stores"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "store",
			Value:  "/etc/whawty/auth-store.yaml",
			Usage:  "path to the store configuration file",
			EnvVar: "WHAWTY_AUTH_STORE_CONFIG",
		},
		cli.BoolTFlag{
			Name:   "do-check",
			Usage:  "run check on base directory before executing command",
			EnvVar: "WHAWTY_AUTH_DO_CHECK",
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
				cli.StringFlag{
					Name:   "listener",
					Value:  "",
					Usage:  "path to the listener configuration file",
					EnvVar: "WHAWTY_AUTH_LISTENER_CONFIG",
				},
			},
			Action: cmdRun,
		},
		{
			Name:  "runsa",
			Usage: "run the auth agent (using systemd socket-activation)",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "listener",
					Value:  "",
					Usage:  "path to the listener configuration file",
					EnvVar: "WHAWTY_AUTH_LISTENER_CONFIG",
				},
			},
			Action: cmdRunSa,
		},
	}

	wdl.Printf("calling app.Run()")
	app.Run(os.Args) //nolint:errcheck
}
