#!/bin/bash

BASE_D=$(realpath "${BASH_SOURCE%/*}")
exec docker run -it --rm -u 1000:1000 -v "$BASE_D/store:/store" -v "$BASE_D/config:/config:ro" --mount type=tmpfs,destination=/run/ssh-master  whawty-auth/sync client 5
