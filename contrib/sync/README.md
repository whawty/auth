# whawty.auth store sync

As the whawty.auth store is just a simple directory you may synchronize multiple
instances using rsync. One way to do this is documented here.

## Introduction

The synchronization is based on a simple master slave system. The master host is an app
running on one machine which might be configured to do local upgrades (see below). One or
more slaves use systemd.timer, rsync and ssh to synchronize the local file store with
the one on the (remote) master host.

### hash parameter-set upgrades

The whawty.auth app can be configured to automatically upgrade password hashes when users
authenticate against it. For this to work the storage backend compares the current default
hashing format and default `param-id`, as set by the store configuration, with the one which
was used to generate the current hash. If the format or `param-id`'s differ it marks the
hash as upgrade-able. After a successful authentication the app now does one of the following:

- **do nothing:** no upgrade will be done, the hash files will stay untouched
- **local upgrades:** do an update operation on the local store
- **remote upgrades:** do an update operation on a remote host via the web API of this host

The first 2 steps are quite self-explanatory. For the third to work the slave host must
be able to reach the masters web API. The uri for the update endpoint can be configured
using the `--do-upgrades` parameter. Mind that the app's web API currently has no support for
https and it is strongly recommended to have a SSL-enabling reverse proxy in front of it.

The remote upgrades are opportunistic which means that a failed update call will be
silently ignored. This is so that a temporary communications problem between master and slave
doesn't slow down local authentication requests. There is also a limit for concurrent
remote upgrade calls a slave will send to the master.

## Setup

### Master

This assumes you have whawty.auth app running as user `whawty-auth`. The store directory is at
`/var/lib/whawty/auth/store`. `/var/lib/whawty/auth` is the home of the user `whawty-auth`.
In order to enable automatic upgrades the web API should be enabled and the app should be
configured to do local upgrades. Also a SSL-enabling reverse proxy is configured to forward
requests coming in on https://whawty-auth-master.example.com/api/ to the app.
Besides that ssh must be running on the host and rsync needs to be installed.

Copy the file `auth-rsyncd.conf` to `/etc/whawty/`. Then run the following commands to create
an `authorized_keys` file for the user `whawty-auth`.

    # mkdir /var/lib/whawty/auth/.ssh
    # chmod 700 /var/lib/whawty/auth/.ssh
    # touch /var/lib/whawty/auth/.ssh/authorized_keys
    # chmod 600 /var/lib/whawty/auth/.ssh/authorized_keys
    # chown -R  whawty-auth:whawty-auth /var/lib/whawty/auth/.ssh

The `authorized_keys` file should contain one line of the following form for each slave:

    command="rsync --server --config /etc/whawty/auth-rsyncd.conf --daemon .",no-X11-forwarding,no-agent-forwarding,no-port-forwarding <<public key of the slave>>

### Slave

This assumes you have whawty.auth app running as user `whawty-auth`. The store directory is at
`/var/lib/whawty/auth/store`. `/var/lib/whawty/auth` is the home of the user `whawty-auth`.
Now use the following commands to create a `.ssh` directory:

    # mkdir /var/lib/whawty/auth/.ssh
    # chmod 700 /var/lib/whawty/auth/.ssh
    # chown whawty-auth:whawty-auth /var/lib/whawty/auth/.ssh
    # sudo -u whawty-auth ssh-keygen -t ed25519

As user `whawty-auth` open/create the file `/var/lib/whawty/auth/.ssh/config` and add the following
to it:

    Host whawty-auth-master
      HostName <hostname or IP of master>
      IdentityFile ~/.ssh/id_ed25519
      IdentitiesOnly yes
      PasswordAuthentication no

Use the contents of `/var/lib/whawty/auth/.ssh/id_ed25519.pub` to add the entry to the
`authorized_keys` file of the master as documented above. You should now be able to sync password
hashes from the master using the following command:

    # sudo -u whawty-auth rsync -rlptv --delete -e ssh whawty-auth-master::store /var/lib/whawty/auth/store

On the first connection you will get asked to accept the ssh fingerprint of the master. If you run
the command a second time no errors/warnings should be shown.
After that you can enable the synchronization by copying the files `whawty-auth-sync.service` and
`whawty-auth-sync.timer` to `/etc/systemd/system` and enabling the timer using the following commands:

    # systemctl daemon-reload
    # systemctl enable whawty-auth-sync.timer
    # systemctl start whawty-auth-sync.timer

If you also want to have automatic `param-id` upgrades on successful logins you need to configure the
slave to do remote upgrades using the the following as an argument to the `--do-upgrades` command line option:

    https://whawty-auth-master.example.com/api/update


## Add a new parameter-set to the store

In order to create a new parameter-set for the store backend you have to generate it. This can be done using the
script `gen-auth-parameter-set.sh`. You have to specify a `param-id` and a `cost` parameter for this parameter-set.
The script will print the new set to STDOUT. Add this line to the auth-store.yaml config.
At first add the new parameter-set to all the slaves' store configurations. Also don't forget to set the default
parameter-set in the config to the new `params-id`. You need to reload the whawty.auth app store config
using SIGHUP for the changes to take effect.
When all slaves are updated and reloaded you can add the new parameter-set to the masters' store configuration as
well. Don't forget to also set the default to the new `param-id` and reload the app using SIGHUP.

After reloading the master users logging in on any app (master or slave) should lead to new upgraded password
hashes. Slaves will sync the changes using the above ssh/rsync setup.
You can and should delete all parameter-sets which are not used anymore. This makes it less likely that an attacker
who might have an old copy of the hashes is able to crack them in the future.
