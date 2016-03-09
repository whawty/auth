#!/bin/sh

WHAWTY_AUTH_STORE="/var/lib/whawty-auth/"
WHAWTY_AUTH_USER="whawty-auth"
WHAWTY_AUTH_GROUP="whawty-auth"

WHAWTY_AUTH_CONF="/etc/whawty-auth/default.json"

###########################################

set -e

HMAC_KEY=`dd if=/dev/random bs=32 count=1 2> /dev/null | base64`

/bin/touch "$WHAWTY_AUTH_CONF"
/bin/chown root:$WHAWTY_AUTH_GROUP "$WHAWTY_AUTH_CONF"
/bin/chmod 640 "$WHAWTY_AUTH_CONF"
/bin/cat <<EOF > "$WHAWTY_AUTH_CONF"
{
    "basedir": "$WHAWTY_AUTH_STORE",
    "scryptauth": {
        "defaultctx": 1,
        "contexts": [
            { "ID": 1, "hmackey": "$HMAC_KEY", "pwcost": 12 }
        ]
    }
}
EOF

/bin/mkdir -p "$WHAWTY_AUTH_STORE"
/bin/chown $WHAWTY_AUTH_USER:$WHAWTY_AUTH_GROUP "$WHAWTY_AUTH_STORE"
/bin/chmod 700 "$WHAWTY_AUTH_STORE"

echo -n "name of first admin user: "
read admin_user
/usr/bin/whawty-auth --conf "$WHAWTY_AUTH_CONF" init "$admin_user"
/bin/chown $WHAWTY_AUTH_USER:$WHAWTY_AUTH_GROUP "$WHAWTY_AUTH_STORE/$admin_user.admin"

exit 0