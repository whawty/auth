# whawty.auth storage schema

The whawty.auth store consists of a single directory which contains a
directory per user. The user directory is named after the user and contains
one file per piece of information about the user.

    /path/to/whawty/auth/base
      adminuser/
        hash                ; password hash of user adminuser
        admin               ; empty file: adminuser is an admin
      gimpf/
        hash
        admin               ; there are multiple admins allowed
      equinox/
        hash                ; password hash of user equinox, a normal user
        totp                ; data of an extension, see below
      fredl/
        hash

This is format v2 of the store. Stores in format v1, which used a file per
user, are described [below](#store-format-v1).

The difference between admins and normal users is that admin users are
allowed to add new users. Also granting admin privileges to normal users
may only be done by admins. An admin is also allowed to change any password.
Normal users may only update their own password.
However this mechanism is not intended as a replacement for a real authorization
database but should only be used by management interfaces of a whawty.auth agent.
You may want to take a look at [whawty.groups](https://github.com/whawty/groups)
if you need an authorization database.

The directory may also contain a `.tmp` directory: agents that update
the whawty.auth base must perform modifications atomically by
writing new files and directories, with a random name, in that directory,
then atomically moving them to their final destination.  As such, `.tmp`
should be backed by the same file system as the whawty.auth base.

Agents that modify the store must hold an exclusive `flock(2)` lock on the
file `.tmp/lock` while they modify a user: adding, updating, upgrading,
changing the admin status and removing users as well as changing data of
extensions. Readers don't need to take the lock since files are only ever
replaced atomically. `flock` might not work reliably with older
kernels or on network file systems like NFS or CIFS. Sharing a store between
machines via a network file system is not supported, use the
[sync mechanism](../contrib/sync/) instead.

Hidden files, i.e. files whose names start with a `.`, must be ignored by
agents, in the base directory as well as in user directories. This allows
tools like rsync to place temporary files there during synchronization.
A valid whawty.auth base directory contains at least one admin which uses a
supported hashing algorithm. If this condition is not met the agent has to
exit with an error.

The following regular expression must match for a user name to be valid:

    [A-Za-z0-9][-_.@A-Za-z0-9]*

A whawty.auth agent may upgrade the hashing algorithm or the algorithm specific
parameter-set during authentication. However if an agent supports this it must
be possible to disable upgrades.


## User directories

A user exists exactly when its directory contains the file `hash`. A directory
without it is not a user: rsync, for example, creates the directory of a new user
before its files arrive. The file `hash` contains a single line which holds the
password hash in the following format:

    <algorithm-identifier>:<last-change>:<paramID>:<format specific string>

`algorithm-identifier` is a unique identifier for the hashing format. This id must
not include a `:`. `last-change` is a UNIX time stamp and represents the last
date/time when the password has been modified. Upgrading the hash to another
parameter-set doesn't modify the password and therefore keeps `last-change`.
`paramID` must be an integer greater than zero that represents a set of
algorithm specific parameters.
A whawty.auth agent should support multiple parameter-sets to allow soft upgrades
of password hashes. The parameter-sets must not be stored in the hash file but have
to be part of the agents configuration.

Everything that decides whether a password alone is enough to authenticate a user
must be part of the `hash` file. Agents can then never see a part of it: rsync
transfers the files of a user one by one.

The empty file `admin` marks a user as admin. All other files hold data of
extensions, see [below](#extensions). Agents must ignore files they don't know.

Agents must add and remove users by moving whole directories: a new user is
built in `.tmp` and then moved into place, a user that gets removed is moved
into `.tmp` first. Agents that read a user without holding the lock should open
the user directory once and read all files relative to it, so they never mix
up the files of a removed user with those of a new user of the same name.

If a whawty.auth agent doesn't support the hashing algorithm of a user it has
to act according to the following rules:

- **on authenticate:** act as if the user does not exist
- **on add:** report an error (user exists)
- **on update:** report an error (won't overwrite unsupported hashes)
- **on delete:** delete the user (a warning may be shown)


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
    length:  tag length (should be > 16bytes)

`salt` is a unique random number with 128bits, `hash` is the output of the following
function:

    argon2id(user_password, salt, time, memory, threads, length)


# Extensions

Extensions store their data in files inside the user directory, one or more files
per extension. Unless an extension defines otherwise, an agent that changes the
data of an extension only replaces the files of that extension. The following
file names are reserved:

| File       | Description                                  |
|------------|----------------------------------------------|
| `totp`     | Time-based One-Time Password Token (RFC6238) |
| `webauthn` | WebAuthn/FIDO2 Token                         |


# Store format v1

In format v1 the store directory contains a file per user instead of a directory.
The file is named after the user, its extension distinguishes between admins and
normal users:

    /path/to/whawty/auth/base
      adminuser.admin       ; password hash for user adminuser which is an admin
      equinox.user          ; password hash for user equinox

The first line of the file has the same format as the `hash` file of format v2.
The rest of the file is reserved for auxiliary data, which no agent ever wrote.
A directory may contain only one file per user. Changing the admin status of a
user renames its file, so readers that don't hold the lock must look for the
user again if they don't find either file.

Agents may support both formats while stores get migrated. In this case:

- A user stored in format v2 takes precedence over v1 files of the same user.
- As long as the store contains users in format v1, new users are added in format v1 too.
- Existing users are always written in their current format.
