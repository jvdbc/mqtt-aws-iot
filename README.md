# Mqtt aws iot project

This project provide a standalone `mqtt client` usable on  `aws iot core` service.

The client can connect to the `aws iot core device gateway` with mqtt or mqtt over websocket, even with http proxy.

## Quick starts

 - help :
```console
$ ./mqtt-clt
```

 - subscribe with mqtt protocol:
 ```console
 $ ./mqtt-clt \
                -endpoint=aws-endpoint-sample.region.amazonaws.com \
                -port=8883 \
                -ca_file=root-certificate-authority-server.pem \
                -cert=client-certificate.pem \
                -pkey=private-key.pem \
                -client_id=i-am-client-one \
                -topic=topic-to-subbscribe/sub-topic
 ```
 
 - publish with mqtt protocol:
 ```console
 $ echo '{"key":"value"}' | ./mqtt-clt \
                                -endpoint=aws-endpoint-sample.region.amazonaws.com \
                                -port=8883 \
                                -ca_file=root-certificate-authority-server.pem \
                                -cert=client-certificate.pem \
                                -pkey=private-key.pem \
                                -client_id=i-am-client-one \
                                -topic=topic-to-publish/sub-topic
                                -publish
 ```

 - subscribe with websocket protocol:
 ```console
HTTPS_PROXY=http://vip-users.proxy.edf.fr:3131
HTTP_PROXY=http://vip-users.proxy.edf.fr:3131
AWS_ACCESS_KEY_ID=<?>
AWS_SECRET_ACCESS_KEY=<?>

 $ ./mqtt-clt \
                -endpoint=aws-endpoint-sample.region.amazonaws.com \
                -port=443 \
                -ca_file=root-certificate-authority-server.pem \
                -cert=client-certificate.pem \
                -pkey=private-key.pem \
                -client_id=i-am-client-one \
                -topic=topic-to-subbscribe/sub-topic \
                -websocket
 ```

## Documentation

 - Doc: [iot core mqtt client](https://goconfluence.enedis.fr/display/TEC/IaC+devinno-pocs+et+aws+iot-core)