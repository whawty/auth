# whawty.auth

[![Build Status](https://travis-ci.org/whawty/auth.svg?branch=master)](https://travis-ci.org/whawty/auth)

whawty.auth is simple file based authentication suite. It uses flat files containing password hashes. These
hashes are currently based on scrypt but the algorithm can be upgraded on the fly. To find out more about
the storage backend read [this file](doc/SCHEMA.md).

This repository contains a golang app which can act as a whawty.auth agent. You can use this app to manage
usernames using a simple web UI. It also offers a _saslauthd_ compatible unix socket to authenticate against it.
There is also a PAM module which uses this socket to bring whawty.auth to PAM applications.

The whawty.auth app can be configured to automatically do upgrades to newer hash algorithms when a user logs
in. This way it is possible to smoothly upgrade to newer/stronger hashing formats. The app also supports
synchronisation between multiple hosts. An sample setup for this can be found [here](app/sync/README.md).

## golang API

### whawty auth store

[![GoDoc](https://godoc.org/github.com/whawty/auth/store?status.svg)](https://godoc.org/github.com/whawty/auth/store)

### cyrus-saslauthd compatible Client/Server

[![GoDoc](https://godoc.org/github.com/whawty/auth/sasl?status.svg)](https://godoc.org/github.com/whawty/auth/sasl)

## Licence

    3-clause BSD

    © 2016 Christian Pointner <equinox@spreadspace.org>
    © 2016 Markus Grüneis <gimpf@gimpf.org>

    whawty.auth makes use of zxcvbn from https://github.com/dropbox/zxcvbn.
    The licence of zxcvbn can be found in the file LICENSE.zxcvbn
