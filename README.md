# whawty.auth

[![Build Status](https://travis-ci.org/whawty/auth.svg?branch=master)](https://travis-ci.org/whawty/auth)

whawty.auth is a simple file based authentication suite. Its **store** uses flat files containing password hashes. These
hashes are currently based on scrypt but the algorithm can be upgraded to newer/stronger formats on the fly.
To find out more about the storage backend read [this file](doc/SCHEMA.md).

This repository contains a golang **app** which can act as a whawty.auth agent. You can use this app to manage
users using a simple web UI.
Install instructions can be found [here](app/README.md).
It also offers a **saslauthd** compatible unix socket to authenticate against it.
This socket is also used by the **PAM** module which can be used to bring whawty.auth to PAM applications.

The whawty.auth app can be configured to automatically do upgrades to newer hash algorithms when a user logs
in. This way it is possible to smoothly upgrade to newer/stronger hashing formats. The app also supports
synchronization between multiple hosts. A sample setup for this can be found [here](app/sync/).

## golang API

### whawty auth store

[![GoDoc](https://godoc.org/github.com/whawty/auth/store?status.svg)](https://godoc.org/github.com/whawty/auth/store)

### cyrus-saslauthd compatible Client/Server

[![GoDoc](https://godoc.org/github.com/whawty/auth/sasl?status.svg)](https://godoc.org/github.com/whawty/auth/sasl)

## License

    3-clause BSD

    © 2016 whawty contributors (see AUTHORS file)

    whawty.auth makes use of zxcvbn from https://github.com/dropbox/zxcvbn.
    The license of zxcvbn can be found in the file LICENSE.zxcvbn
