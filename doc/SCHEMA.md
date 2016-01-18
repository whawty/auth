# whawty storage schema

The whawty store consists of a single directory which contains all
usernames and password hashes in flat files. Password files are named
after the user. The file extension is used to distinguish between admin
and normal user.

    /path/to/whawty/base
      adminuser.admin       ; password hash for user adminuser which is an admin
      gimpf.admin           ; there are multiple admins allowed
      equinox.user          ; password hash for user equinox
      fredl.user            ; password hash for user fredl

The directory must not contain any other files. A valid whawty base directory
contains at least one admin file which uses an supported hashing format.
Furthermore a directory may contain only one hash file per user.
If this conditions are not met the agent has to exit with an error.

If a whawty agent doesn't support the hashing format of a file it has to act
according to the following rules:

- on authenticate: ignore the file and act as if the user does not exist
- on add: report an error (user exists)
- on update: report an error (won't overwrite unsupported formats)
- on delete: delete the file (a warning may be shown)

Uernames must only contain the following characters: [-_@A-Za-z0-9]

The difference between admins and normal users is that admin users are
allowed to add new users. Also granting admin privileges to normal users
may only be done by admins. An admin is also allowed to change any password.
Normal users may only update their own password.

A whawty agent may upgrade the hashing algorihtm to an other(newer) format
during authentication.
However if an agent supports this it must be possible to disable upgrades.

The contents of the files depend on the hashing algorithm used. For now
the only supported algorightm is scrypt which has the following structure:

    tba...
