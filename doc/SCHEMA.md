# whawty.auth storage schema

The whawty.auth store consists of a single directory which contains all
user names and password hashes in flat files. Password files are named
after the user. The file extension is used to distinguish between admin
and normal user.

    /path/to/whawty/auth/base
      adminuser.admin       ; password hash for user adminuser which is an admin
      gimpf.admin           ; there are multiple admins allowed
      equinox.user          ; password hash for user equinox
      fredl.user            ; password hash for user fredl

The difference between admins and normal users is that admin users are
allowed to add new users. Also granting admin privileges to normal users
may only be done by admins. An admin is also allowed to change any password.
Normal users may only update their own password.
However this mechanism is not intended as a replacement for a real authorization
database but should only be used by management interfaces of a whawty.auth agent.
You may want to take a look at [whawty.groups](https://github.com/whawty/groups)
if you need an authorization database.

The directory may also contain a `.tmp` directory: agents that update
the whawty.auth base must perform file modifications atomically by
writing new files, with a random name, in that directory, then
atomically moving them to their final destination.  As such, `.tmp`
should be backed by the same file system as the whawty.auth base.

The directory must not contain any other files. A valid whawty.auth base
directory contains at least one admin file which uses a supported hashing
algorithm.
Furthermore a directory may contain only one hash file per user.
If this conditions are not met the agent has to exit with an error.

If a whawty.auth agent doesn't support the hashing algorithm of a file it has
to act according to the following rules:

- **on authenticate:** ignore the file and act as if the user does not exist
- **on add:** report an error (user exists)
- **on update:** report an error (won't overwrite unsupported hashes)
- **on delete:** delete the file (a warning may be shown)

The following regular expression must match for a user name to be valid:

    [A-Za-z0-9][-_.@A-Za-z0-9]*

A whawty.auth agent may upgrade the hashing algorithm or the algorithm specific
parameter-set during authentication. However if an agent supports this it must
be possible to disable upgrades.


## File Format

The first line of the file contains the password hash which has the following format:

    <algorithm-identifier>:<last-change>:<paramID>:<format specific string>

`algorithm-identifier` is a unique identifier for the hashing format. This id must
not include a `:`. `last-change` is a UNIX time stamp and represents the last
date/time when the password has been modified. `paramID` must be an integer greater
than zero that represents a set of algorithm specific parameters.
A whawty.auth agent should support multiple parameter-sets to allow soft upgrades
of password hashes. The parameter-sets must not be stored in the hash file but have
to be part of the agents configuration.

The rest of the file (first line excluded) is reserved for auxiliary data.


# Hashing algorithms

For now the only supported algorithms are scrypt inside hmac-sha256 and argon2id.

## hmac_sha256_scrypt

This hashing algorithm has the following structure:

    hmac_sha256_scrypt:<last-change>:<paramID>:base64(salt):base64(hash)

The following parameters are needed:

    hmackey: the key for the hmac-sha256
    cost:    (1<<cost) forms the scrypt parameter N
    r:       the scrypt parameter r
    p:       the scrypt parameter p

`salt` is a unique random number with 256bits, `hash` is the output of the following
function:

    hmac_sha256(scrypt(user_password, salt, N=(1<<cost), r, p, len=32), hmackey)

## argon2id

This hashing algorithm has the following structure:

    argon2id:<last-change>:<paramID>:base64(salt):base64(hash)

The following parameters are needed:

    time:    number of iterations
    memory:  memory size
    threads: degree of paralellism
    len:     tag length (should be > 16bytes)

`salt` is a unique random number with 128bits, `hash` is the output of the following
function:

    argon2id(user_password, salt, time, memory, threads, len)


## Auxiliary Data

The auxiliary data associated to a user is stored in the user's file, after the
first line.  It is organized as key value pairs.

A file may contain 0 or more lines of auxiliary data,
each of which starts with a unique identifier:

    <identifier>: <base64(data)>

`identifier` must not contain a `:` and must be unique (see table below). For now
aux-data is only used for 2/multi-factor authentication schemes but might be used
for other purposes as well. The values are base64 encoded and besides this encoding
shouldn't be mangled with by a whawty.auth agent.


| Identifier | Description                                  |
|------------|----------------------------------------------|
| `u2f`      | FIDO Universal 2nd Factor Token              |
| `totp`     | Time-based One-Time Password Token (RFC6238) |
