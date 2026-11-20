# whawty.auth

whawty.auth is a simple file based authentication suite. Its **store** uses a directory per user which contains the
password hash and other information about the user. The hashes are based on scrypt or argon2id, and the algorithm can
be upgraded to newer/stronger formats on the fly.
To find out more about the storage backend read [this file](doc/SCHEMA.md).

This repository contains a golang **app** which can act as a whawty.auth agent. You can use this app to manage
users using a simple web UI.
Install instructions can be found [here](cmd/whawty-auth/README.md).
It also offers a **saslauthd** compatible unix socket to authenticate against it.
This socket is also used by the **PAM** module which can be used to bring whawty.auth to PAM applications.

The whawty.auth app can be configured to automatically do upgrades to newer hash algorithms when a user logs
in. This way it is possible to smoothly upgrade to newer/stronger hashing formats. The app also supports
synchronization between multiple hosts. A sample setup for this can be found [here](contrib/sync/).
Writers coordinate using `flock(2)`, which might not work with older kernels or network file systems like
NFS or CIFS. Sharing the store via a network file system is not supported, use the sync mechanism instead.

## Migrating a store to format v2

Stores created by older versions use format v1, a file per user. Agents support both formats, so a store can be
migrated in place:

1. Upgrade every agent that uses the store, on every host, to a version that supports format v2. This includes
   programs that embed the store library, like [nginx-sso](https://github.com/whawty/nginx-sso). Older agents
   refuse a migrated store: they don't find any user, and `check` fails.
2. On the master, run `whawty-auth --store <config> migrate`. It converts one user at a time while holding the store
   lock, so logins keep working, and it can be run again if it got interrupted. Until a store has been migrated,
   new users are added in format v1 as well.
3. Slaves get the migrated store with the next synchronization. Make sure rsync runs with `--delete-delay`, see
   [contrib/sync](contrib/sync/), so the old files are only removed after the new ones are in place. There is one
   exception: if a user is named like another user plus `.user` or `.admin`, e.g. `alice` and `alice.user`, rsync
   has to delete the old file of the shorter one right away to make room for the directory of the other. That user
   can't log in on the slave until the transfer has finished.

## golang API

### whawty auth store

[![GoDoc](https://godoc.org/github.com/whawty/auth/store?status.svg)](https://godoc.org/github.com/whawty/auth/store)

### cyrus-saslauthd compatible Client/Server

[![GoDoc](https://godoc.org/github.com/whawty/auth/sasl?status.svg)](https://godoc.org/github.com/whawty/auth/sasl)

## License

    3-clause BSD

    © 2016-2026 whawty contributors (see AUTHORS file)

    The web interface of whawty.auth contains zxcvbn from
    https://github.com/dropbox/zxcvbn (MIT License, see LICENSE.zxcvbn) and
    icons from Lucide, https://lucide.dev (ISC License, some icons MIT
    License). See ui/VENDORED.md for details on all third-party files.
