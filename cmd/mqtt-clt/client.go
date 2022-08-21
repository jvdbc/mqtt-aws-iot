package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	mqtt "github.com/eclipse/paho.mqtt.golang"
)

const (
	// 292 years
	MaxDuration      time.Duration = 1<<63 - 1
	IotServiceName                 = "iotdevicegateway"
	EmptyPayloadHash               = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	PublishAction mqttAction = iota
	SubscribeAction
)

func If[T any](cond bool, vtrue, vfalse T) T {
	if cond {
		return vtrue
	}
	return vfalse
}

func New(endpoint string, port uint, topic string, clientid string, websocket bool, awsregion string, publish bool) *Client {
	clt := &Client{
		Topic:      topic,
		ClientId:   clientid,
		Websocket:  websocket,
		AwsRegion:  awsregion,
		mqttAction: If(publish, PublishAction, SubscribeAction),
	}

	clt.
		ctrlC().
		initBrokerUrl(endpoint, port)

	return clt
}

type mqttAction int16

func (a mqttAction) isPublishAction() bool {
	return a == PublishAction
}

func (a mqttAction) isSubscribeAction() bool {
	return a == SubscribeAction
}

type Client struct {
	Topic       string
	Websocket   bool
	InputMsg    []byte
	AwsRegion   string
	BrokerUrl   string
	ClientId    string
	err         error
	config      *tls.Config
	mqttCltOpts *mqtt.ClientOptions
	mqttClt     mqtt.Client
	mqttAction
}

func (h *Client) CloseMqtt(quiesce uint) *Client {
	// no exit if err (used by fatalIfErr)
	if h.mqttClt != nil && h.mqttClt.IsConnected() {

		info("Close mqtt\n")
		h.mqttClt.Disconnect(quiesce)
		time.Sleep(time.Duration(quiesce))
	}

	return h
}

func (h *Client) Config(cafile string, keyfile string, certfile string) *Client {
	if h.abort() {
		return h
	}

	return h.
		tlsConfig(cafile, keyfile, certfile).
		cltOpts()
}

func (h *Client) abort() bool {
	return h.err != nil
}

func (h *Client) error(format string, a ...any) *Client {
	h.err = fmt.Errorf(format, a...)
	return h
}

// https://github.com/at-wat/mqtt-go/blob/master/examples/wss-presign-url/main.go
// https://github.com/seqsense/aws-iot-device-sdk-go/blob/master/presigner/presign.go
// https://aws.github.io/aws-sdk-go-v2/docs/making-requests/
func (h *Client) sigV4WebsocketOpenConnection(uri *url.URL, options mqtt.ClientOptions) (net.Conn, error) {
	var cfg aws.Config
	var err error
	var url *url.URL
	var creds aws.Credentials
	var presignedUrl string
	var presignedHeader http.Header

	ctx := context.TODO()
	if cfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(h.AwsRegion)); err != nil {
		return nil, err
	}

	signer := v4.NewSigner()
	if url, err = url.Parse(h.BrokerUrl); err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: "GET",
		URL:    url,
	}

	if creds, err = cfg.Credentials.Retrieve(ctx); err != nil {
		return nil, err
	}

	if presignedUrl, presignedHeader, err = signer.PresignHTTP(
		ctx, creds, req, EmptyPayloadHash, IotServiceName, cfg.Region, time.Now()); err != nil {
		return nil, err
	}

	return mqtt.NewWebsocket(presignedUrl, h.config, 20*time.Second, presignedHeader, nil)
}

// Gracefully shutdown on ctrl+c
// https://golangcode.com/handle-ctrl-c-exit-in-terminal/
func (h *Client) ctrlC() *Client {
	if h.abort() {
		return h
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-quit
		h.CloseMqtt(250)
		info("Bye\n")
		os.Exit(0)
	}()
	return h
}

func (h *Client) initBrokerUrl(endpoint string, port uint) *Client {
	if h.abort() {
		return h
	}

	if h.Websocket {
		// 86400 => 24h
		// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
		h.BrokerUrl = fmt.Sprintf("wss://%s:%v/mqtt?X-Amz-Expires=86400", endpoint, port)
	} else {
		h.BrokerUrl = fmt.Sprintf("tls://%s:%v", endpoint, port)
	}

	return h
}

// https://www.emqx.com/en/blog/how-to-use-mqtt-in-golang
// https://github.com/aws/aws-sdk-go/issues/820
// https://github.com/seqsense/aws-iot-device-sdk-go/blob/master/dialer.go
// https://docs.aws.amazon.com/sdk-for-go/api/aws/signer/v4/
// https://github.com/aws/aws-sdk-go/blob/main/aws/signer/v4/v4.go
func (h *Client) tlsConfig(cafile string, keyfile string, certfile string) *Client {
	if h.abort() {
		return h
	}

	// Create tls.Config with desired tls properties
	h.config = &tls.Config{
		// ClientAuth = whether to request cert from server.
		// Since the server is set up for SSL, this happens
		// anyways.
		ClientAuth: tls.NoClientCert,
		// ClientCAs = certs used to validate client cert.
		ClientCAs: nil,
	}

	if h.Websocket {
		h.config.InsecureSkipVerify = true
	} else {
		// Import trusted certificates from CAfile.pem.
		certpool := x509.NewCertPool()
		pemCerts, err := ioutil.ReadFile(cafile)
		if err != nil {
			return h.error("Failed to read root ca file: %v", err)
		}

		certpool.AppendCertsFromPEM(pemCerts)

		// Import client certificate/key pair.
		cert, err := tls.LoadX509KeyPair(certfile, keyfile)
		if err != nil {
			return h.error("Failed to load cert/pkey files: %v", err)
		}

		h.config.RootCAs = certpool
		h.config.Certificates = []tls.Certificate{cert}
	}

	return h
}

func (h *Client) cltOpts() *Client {
	if h.abort() {
		return h
	}

	h.mqttCltOpts = mqtt.NewClientOptions().
		AddBroker(h.BrokerUrl).
		SetClientID(h.ClientId).
		SetTLSConfig(h.config).
		SetDefaultPublishHandler(func(client mqtt.Client, msg mqtt.Message) {
			log.Printf("Received message on topic: %s\n", msg.Topic())
			fmt.Printf("%s\n", msg.Payload())
		})

	if h.Websocket {
		h.mqttCltOpts.SetCustomOpenConnectionFn(h.sigV4WebsocketOpenConnection)
	}

	return h
}

// https://flaviocopes.com/go-shell-pipes/
func readStdin() ([]byte, error) {
	stdInfo, err := os.Stdin.Stat()

	if err != nil {
		return nil, fmt.Errorf("Failed to read from stdin: %v", err)
	}

	if (stdInfo.Mode() & os.ModeCharDevice) != 0 {
		return nil, fmt.Errorf("Publish is intended to work with input pipe message")
	}

	var lines []byte
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		lines = append(lines, scanner.Bytes()...)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("Failed to read input message %v", err)
	}

	return lines, nil
}

func (h *Client) connect() *Client {
	if h.abort() {
		return h
	}

	if h.mqttCltOpts == nil {
		return h.error("Mqtt client options is nil")
	}

	info("Open mqtt\n")
	h.mqttClt = mqtt.NewClient(h.mqttCltOpts)

	if token := h.mqttClt.Connect(); token.Wait() && token.Error() != nil {
		return h.error("Failed to create mqtt connection: %v", token.Error())
	}

	return h
}

func (h *Client) publish() *Client {
	if h.abort() || !h.isPublishAction() {
		return h
	}

	if h.mqttClt == nil {
		return h.error("Mqtt client options is nil")
	}

	inputMsg, err := readStdin()
	if err != nil {
		return h.error("Failed to read stdin: %v", err)
	}

	info("Send message to %s\n", h.Topic)
	if token := h.mqttClt.Publish(h.Topic, 0, false, inputMsg); token.Wait() && token.Error() != nil {
		return h.error("Failed to send message: %v", token.Error())
	}

	return h
}

func (h *Client) subscribe() *Client {
	if h.abort() || !h.isSubscribeAction() {
		return h
	}

	if h.mqttClt == nil {
		return h.error("Mqtt client options is nil")
	}

	info("Subscribe on %s\n", h.Topic)
	if token := h.mqttClt.Subscribe(h.Topic, 0, nil); token.Wait() && token.Error() != nil {
		return h.error("Failed to subscribe: %v", token.Error())
	}

	return h
}

func (h *Client) fatalIfErr() *Client {
	if h.err != nil {
		h.CloseMqtt(250)
		log.Fatalf("%s\n", h.err)
	}

	return h
}

func (h *Client) waitMessages() *Client {
	if h.abort() || !h.isSubscribeAction() {
		return h
	}

	// TODO better wait with quit base on chan ?
	info("Wait messages...\n")
	time.Sleep(MaxDuration)

	return h
}
