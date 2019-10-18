#!/bin/bash

set -e
function finish {
    if [ -n "$CARAFE_PID" ]; then
        kill $CARAFE_PID
    fi
}
function err {
    echo "Error!" 1>&2
    exit 1
}
trap finish EXIT
trap err ERR

../carafe &
CARAFE_PID=$!
sleep 1
curl -s 'http://127.0.0.1:8080/headers' | grep 'Headers:'
curl -s 'http://127.0.0.1:8080/var/var_here' | grep 'var_here'

echo OK
