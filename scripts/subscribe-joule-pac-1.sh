#!/usr/bin/env bash

./build/linux/amd64/mqtt-clt \
    -ca_file=./assets/joule-pac-1/root-CA.cert.pem \
    -cert=./assets/joule-pac-1/cert.pem \
    -pkey=./assets/joule-pac-1/private.key \
    -client_id=joule-pac-1 \
    -topic=joule-pac-1/#
