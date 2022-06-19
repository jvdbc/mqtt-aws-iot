#!/usr/bin/env bash

# '{"state": { "desired": { "deviceId": "joule-pac-1", "meterId" : "9876543210","addressIp" : "192.168.0.1"}}}'

cat ./assets/publish-shadow.json | ./build/linux/amd64/sc-mqtt-clt \
                -ca_file=./assets/joule-pac-1/root-CA.cert.pem \
                -cert=./assets/joule-pac-1/cert.pem \
                -pkey=./assets/joule-pac-1/private.key \
                -client_id=joule-pac-1 \
                -topic=joule-pac-1/topic-2 \
                -publish
