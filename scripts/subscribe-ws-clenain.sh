#!/usr/bin/env bash

HTTPS_PROXY=http://vip-users.proxy.edf.fr:3131
HTTP_PROXY=http://vip-users.proxy.edf.fr:3131
AWS_ACCESS_KEY_ID=<?>
AWS_SECRET_ACCESS_KEY=<?>

./build/linux/amd64/mqtt-clt \
    -port 443 \
    -endpoint a2m9dujvq8fryc-ats.iot.eu-west-1.amazonaws.com \
    -topic joule-pac-2/dev/topic-1 \
    -client_id clenain \
    -websocket
