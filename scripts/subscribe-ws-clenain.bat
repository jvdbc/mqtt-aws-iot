@echo off

SET HTTPS_PROXY=http://vip-users.proxy.edf.fr:3131
SET HTTP_PROXY=http://vip-users.proxy.edf.fr:3131
SET AWS_ACCESS_KEY_ID=<?>
SET AWS_SECRET_ACCESS_KEY=<?>

build\windows\amd64\mqtt-clt ^
    -port 443 ^
    -endpoint a2m9dujvq8fryc-ats.iot.eu-west-1.amazonaws.com ^
    -topic joule-pac-2/dev/topic-1 ^
    -client_id clenain ^
    -websocket
