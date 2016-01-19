# whawty.auth storage schema

The whawty.auth store consists of a single directory which contains all
usernames and password hashes in flat files. Password files are named
after the user. The file extension is used to distinguish between admin
and normal user.

    /path/to/whawty/auth/base
      adminuser.admin       ; password hash for user adminuser which is an admin
      gimpf.admin           ; there are multiple admins allowed
      equinox.user          ; password hash for user equinox
      fredl.user            ; password hash for user fredl

The directory must not contain any other files. A valid whawty.auth base
directory contains at least one admin file which uses a supported hashing
format.
Furthermore a directory may contain only one hash file per user.
If this conditions are not met the agent has to exit with an error.

If a whawty.auth agent doesn't support the hashing format of a file it has
to act according to the following rules:

- on authenticate: ignore the file and act as if the user does not exist
- on add: report an error (user exists)
- on update: report an error (won't overwrite unsupported formats)
- on delete: delete the file (a warning may be shown)

Usernames must only contain the following characters: [-_@A-Za-z0-9]

The difference between admins and normal users is that admin users are
allowed to add new users. Also granting admin privileges to normal users
may only be done by admins. An admin is also allowed to change any password.
Normal users may only update their own password.

A whawty.auth agent may upgrade the hashing algorihtm to an other(newer)
format during authentication.
However if an agent supports this it must be possible to disable upgrades.

The contents of the files depend on the hashing algorithm used. For now
the only supported algorithm is scrypt inside hmac-sha256 which has the
following structure:

    ctxID:base64(salt):base64(hash)

ctxID is a identifier for a set of parameters which must be stored outside of
the base directory. The parameters needed are:

    server_key: the key for the hmac-sha256
    pw_cost:    (1<<pw_cost) forms the scrypt parameter N
    p:          the scrypt parameter p
    r:          the scrypt parameter r

salt is a random number with 256bits, hash is the output of the following function

    hmac_sha256(scrypt(user_password, salt), server_key)
