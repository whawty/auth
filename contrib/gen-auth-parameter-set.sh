#!/bin/sh

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <parameter-set-id> <cost>"
  exit 1
fi

HMAC_KEY=`dd if=/dev/urandom bs=32 count=1 2> /dev/null | base64`

echo "  - id: $1"
echo "    scryptauth:
echo "      hmackey: \"$HMAC_KEY\""
echo "      cost: $2"

exit 0
