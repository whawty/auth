#!/bin/sh

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <context-id> <pwcost>"
  exit 1
fi

HMAC_KEY=`dd if=/dev/urandom bs=32 count=1 2> /dev/null | base64`

echo '{ "ID": '$1', "hmackey": "'$HMAC_KEY'", "pwcost": '$2' }'

exit 0

