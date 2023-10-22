#!/bin/sh

MODE=$1
CLIENT_SLEEP=$2
if [ -z "$MODE" ]; then
  MODE="server"
fi
if [ -z "$CLIENT_SLEEP" ]; then
  CLIENT_SLEEP=60
fi

export LD_PRELOAD=libnss_wrapper.so
export NSS_WRAPPER_PASSWD=/config/passwd
export NSS_WRAPPER_GROUP=/config/group

case "$MODE" in
  server)
    exec /usr/sbin/sshd -D -e -f /config/sshd_config
    ;;
  client)
    while
     /usr/bin/rsync -rtpW --delete --delete-delay --delay-updates --partial-dir=.tmp -e 'ssh -F /config/ssh_config' 'rsync://whawty-auth-master/store' '/store' || /bin/true
    do sleep "$CLIENT_SLEEP"; done
    ;;
  *)
    echo "unknown mode $MODE, must be server or client"
    ;;
esac

return 1
