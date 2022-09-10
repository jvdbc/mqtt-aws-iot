package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
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
)

func If[T any](cond bool, vtrue, vfalse T) T {
	if cond {
		return vtrue
	}
	return vfalse
}

func New(endpoint string, port uint, clientid string) *Client {
	clt := &Client{
		Endpoint: endpoint,
		Port:     port,
		ClientId: clientid,
	}

	clt.
		addCtrlC()

	return clt
}

type Client struct {
	Endpoint  string
	Port      uint
	Topic     string
	InputMsg  []byte
	AwsRegion string
	ClientId  string

	mqttClt mqtt.Client
}

func (h *Client) CloseMqtt(quiesce uint) {
	// no exit if err (used by fatalIfErr)
	if h.mqttClt != nil && h.mqttClt.IsConnected() {
		infof("close mqtt\n")
		h.mqttClt.Disconnect(quiesce)
		time.Sleep(time.Duration(quiesce))
	}
}

func (h *Client) Connect(cafile string, keyfile string, certfile string) error {
	var tlsConfig *tls.Config
	var err error

	if tlsConfig, err = newTlsConfig(cafile, keyfile, certfile); err != nil {
		return fmt.Errorf("failed to create mqtt connection: %w", err)
	}

	mqttCltOpts := newCltOpts(
		fmt.Sprintf("tls://%s:%v", h.Endpoint, h.Port),
		h.ClientId,
		tlsConfig)

	infof("open mqtt\n")
	h.mqttClt = mqtt.NewClient(mqttCltOpts)

	if token := h.mqttClt.Connect(); token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to create mqtt connection: %w", token.Error())
	}

	return nil
}

func (h *Client) ConnectWS(awsRegion string) error {
	h.AwsRegion = awsRegion

	// 86400 => 24h
	// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
	mqttCltOpts := newCltOpts(
		fmt.Sprintf("wss://%s:%v/mqtt?X-Amz-Expires=86400", h.Endpoint, h.Port),
		h.ClientId,
		newTlsConfigWS())

	mqttCltOpts.SetCustomOpenConnectionFn(h.sigV4WebsocketOpenConnection)

	infof("open mqtt on websocket\n")
	h.mqttClt = mqtt.NewClient(mqttCltOpts)

	if token := h.mqttClt.Connect(); token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to create mqtt on websocket connection: %w", token.Error())
	}

	return nil
}

func (h *Client) Publish(topic string, inputMsg []byte) error {
	if h.mqttClt == nil {
		return errors.New("mqtt client is nil, you need to call Connect before publish")
	}

	infof("send message to %s\n", topic)
	if token := h.mqttClt.Publish(topic, 0, false, inputMsg); token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to send message: %w", token.Error())
	}

	return nil
}

func (h *Client) Subscribe(topic string) error {
	if h.mqttClt == nil {
		return errors.New("mqtt client is nil, you need to call Connect before Subscribe")
	}

	infof("subscribe on %s\n", topic)
	if token := h.mqttClt.Subscribe(topic, 0, nil); token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to subscribe: %w", token.Error())
	}

	return nil
}

// https://github.com/at-wat/mqtt-go/blob/master/examples/wss-presign-url/main.go
// https://github.com/seqsense/aws-iot-device-sdk-go/blob/master/presigner/presign.go
// https://aws.github.io/aws-sdk-go-v2/docs/making-requests/
func (h *Client) sigV4WebsocketOpenConnection(url *url.URL, options mqtt.ClientOptions) (net.Conn, error) {
	var cfg aws.Config
	var err error
	var creds aws.Credentials
	var presignedUrl string
	var presignedHeader http.Header

	ctx := context.TODO()
	if cfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(h.AwsRegion)); err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: "GET",
		URL:    url,
	}

	if creds, err = cfg.Credentials.Retrieve(ctx); err != nil {
		return nil, err
	}

	signer := v4.NewSigner()
	if presignedUrl, presignedHeader, err = signer.PresignHTTP(
		ctx, creds, req, EmptyPayloadHash, IotServiceName, cfg.Region, time.Now()); err != nil {
		return nil, err
	}

	return mqtt.NewWebsocket(presignedUrl, options.TLSConfig, 20*time.Second, presignedHeader, nil)
}

// Gracefully shutdown on ctrl+c
// https://golangcode.com/handle-ctrl-c-exit-in-terminal/
func (h *Client) addCtrlC() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-quit
		h.CloseMqtt(250)
		infof("bye\n")
		os.Exit(0)
	}()
}

// https://www.emqx.com/en/blog/how-to-use-mqtt-in-golang
// https://github.com/aws/aws-sdk-go/issues/820
// https://github.com/seqsense/aws-iot-device-sdk-go/blob/master/dialer.go
// https://docs.aws.amazon.com/sdk-for-go/api/aws/signer/v4/
// https://github.com/aws/aws-sdk-go/blob/main/aws/signer/v4/v4.go
func newTlsConfig(cafile string, keyfile string, certfile string) (*tls.Config, error) {
	// Create tls.Config with desired tls properties
	tlsConfig := &tls.Config{
		// ClientAuth = whether to request cert from server.
		// Since the server is set up for SSL, this happens
		// anyways.
		ClientAuth: tls.NoClientCert,
		// ClientCAs = certs used to validate client cert.
		ClientCAs: nil,
	}

	certpool := x509.NewCertPool()
	pemCerts, err := ioutil.ReadFile(cafile)
	if err != nil {
		return nil, fmt.Errorf("failed to read root ca file: %w", err)
	}

	certpool.AppendCertsFromPEM(pemCerts)

	// Import client certificate/key pair.
	cert, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return nil, fmt.Errorf("failed to load cert/pkey files: %w", err)
	}

	tlsConfig.RootCAs = certpool
	tlsConfig.Certificates = []tls.Certificate{cert}

	return tlsConfig, nil
}

func newTlsConfigWS() *tls.Config {
	// Create tls.Config with desired tls properties
	tlsConfig := &tls.Config{
		// ClientAuth = whether to request cert from server.
		// Since the server is set up for SSL, this happens
		// anyways.
		ClientAuth: tls.NoClientCert,
		// ClientCAs = certs used to validate client cert.
		ClientCAs: nil,
	}

	tlsConfig.InsecureSkipVerify = true

	return tlsConfig
}

func newCltOpts(server string, clientId string, tlsConfig *tls.Config) *mqtt.ClientOptions {
	return mqtt.NewClientOptions().
		AddBroker(server).
		SetClientID(clientId).
		SetTLSConfig(tlsConfig).
		SetDefaultPublishHandler(func(client mqtt.Client, msg mqtt.Message) {
			infof("received message on topic: %s\n", msg.Topic())
			fmt.Printf("%s\n", msg.Payload())
		})
}
