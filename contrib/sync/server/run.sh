#!/bin/bash

BASE_D=$(realpath "${BASH_SOURCE%/*}")
exec docker run -it --rm -p 4022:4022 -u 1000:1000 -v "$BASE_D/store:/store:ro" -v "$BASE_D/config:/config:ro" whawty-auth/sync server
