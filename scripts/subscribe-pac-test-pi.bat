@echo off

.\build\windows\amd64\sc-mqtt-clt ^
    -ca_file=./assets/pac-test-pi/root-CA.cert.pem ^
    -cert=./assets/pac-test-pi/cert.pem ^
    -pkey=./assets/pac-test-pi/private.key ^
    -client_id=pac-test-pi ^
    -topic=joule-pac-1/#
