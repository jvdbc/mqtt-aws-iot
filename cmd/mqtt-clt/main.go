package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
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

	// https://github.com/eclipse/paho.mqtt.golang
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"golang.org/x/net/proxy"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
)

type mqttAction int16

const (
	AwsAccessKeyEnvVarName = "AWS_ACCESS_KEY_ID"
	AwsSecretKeyEnvVarName = "AWS_SECRET_ACCESS_KEY"
	// 292 years
	MaxDuration      time.Duration = 1<<63 - 1
	IotServiceName                 = "iotdevicegateway"
	EmptyPayloadHash               = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	PublishAction mqttAction = iota
	SubscribeAction
)

func (a mqttAction) isPublishAction() bool {
	return a == PublishAction
}

func (a mqttAction) isSubscribeAction() bool {
	return a == SubscribeAction
}

type handler struct {
	err         error
	topic       string
	config      *tls.Config
	mqttCltOpts *mqtt.ClientOptions
	mqttClt     mqtt.Client
	mqttAction
	inputMsg  []byte
	websocket bool
	awsRegion string
	serverUrl string
}

func (h *handler) abort() bool {
	return h.err != nil
}

func (h *handler) error(format string, a ...any) *handler {
	h.err = fmt.Errorf(format, a...)
	return h
}

func (h *handler) closeMqtt(quiesce uint) *handler {
	// no exit if err (used by fatalIfErr)
	if h.mqttClt != nil && h.mqttClt.IsConnected() {

		info("Close mqtt\n")
		h.mqttClt.Disconnect(quiesce)
		time.Sleep(time.Duration(quiesce))
	}

	return h
}

// https://github.com/at-wat/mqtt-go/blob/master/examples/wss-presign-url/main.go
// https://github.com/seqsense/aws-iot-device-sdk-go/blob/master/presigner/presign.go
// https://aws.github.io/aws-sdk-go-v2/docs/making-requests/
func (h handler) sigV4WebsocketOpenConnection(uri *url.URL, options mqtt.ClientOptions) (net.Conn, error) {
	var cfg aws.Config
	var err error
	var url *url.URL
	var creds aws.Credentials
	var presignedUrl string
	var presignedHeader http.Header

	ctx := context.TODO()
	if cfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(h.awsRegion)); err != nil {
		return nil, err
	}

	signer := v4.NewSigner()
	if url, err = url.Parse(h.serverUrl); err != nil {
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
func (h *handler) ctrlC() *handler {
	if h.abort() {
		return h
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-quit
		h.closeMqtt(250)
		info("Bye\n")
		os.Exit(0)
	}()
	return h
}

// https://www.emqx.com/en/blog/how-to-use-mqtt-in-golang
// https://github.com/aws/aws-sdk-go/issues/820
// https://github.com/seqsense/aws-iot-device-sdk-go/blob/master/dialer.go
// https://docs.aws.amazon.com/sdk-for-go/api/aws/signer/v4/
// https://github.com/aws/aws-sdk-go/blob/main/aws/signer/v4/v4.go
func (h *handler) tlsConfig(cafile string, pkeyfile string, certfile string) *handler {
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

	if h.websocket {
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
		cert, err := tls.LoadX509KeyPair(certfile, pkeyfile)
		if err != nil {
			return h.error("Failed to load cert/pkey files: %v", err)
		}

		h.config.RootCAs = certpool
		h.config.Certificates = []tls.Certificate{cert}
	}

	return h
}

func (h *handler) brokerUri(endpoint string, port uint) *handler {
	if h.abort() {
		return h
	}

	if h.websocket {
		// 86400 => 24h
		// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
		h.serverUrl = fmt.Sprintf("wss://%s:%v/mqtt?X-Amz-Expires=86400", endpoint, port)
	} else {
		h.serverUrl = fmt.Sprintf("tls://%s:%v", endpoint, port)
	}

	return h
}

func (h *handler) cltOpts(clientid string) *handler {
	if h.abort() {
		return h
	}

	h.mqttCltOpts = mqtt.NewClientOptions().
		AddBroker(h.serverUrl).
		SetClientID(clientid).
		SetTLSConfig(h.config).
		SetDefaultPublishHandler(func(client mqtt.Client, msg mqtt.Message) {
			log.Printf("Received message on topic: %s\n", msg.Topic())
			fmt.Printf("%s\n", msg.Payload())
		})

	if h.websocket {
		h.mqttCltOpts.SetCustomOpenConnectionFn(h.sigV4WebsocketOpenConnection)
	}

	return h
}

func (h *handler) connect() *handler {
	if h.abort() {
		return h
	}

	info("Open mqtt\n")
	h.mqttClt = mqtt.NewClient(h.mqttCltOpts)

	if token := h.mqttClt.Connect(); token.Wait() && token.Error() != nil {
		return h.error("Failed to create mqtt connection: %v", token.Error())
	}

	return h
}

// https://flaviocopes.com/go-shell-pipes/
func (h *handler) readStdin() *handler {
	if h.abort() || !h.isPublishAction() {
		return h
	}

	stdInfo, err := os.Stdin.Stat()

	if err != nil {
		return h.error("Failed to read from stdin: %v", err)
	}

	if (stdInfo.Mode() & os.ModeCharDevice) != 0 {
		return h.error("Publish is intended to work with input pipe message")
	}

	var lines []byte
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		lines = append(lines, scanner.Bytes()...)
	}

	if err := scanner.Err(); err != nil {
		return h.error("Failed to read input message %v", err)
	}

	h.inputMsg = lines

	return h
}

func (h *handler) publish() *handler {
	if h.abort() || !h.isPublishAction() {
		return h
	}

	info("Send message to %s\n", h.topic)
	if token := h.mqttClt.Publish(h.topic, 0, false, h.inputMsg); token.Wait() && token.Error() != nil {
		h.error("Failed to send message: %v", token.Error())
	}

	return h
}

func (h *handler) subscribe() *handler {
	if h.abort() || !h.isSubscribeAction() {
		return h
	}

	info("Subscribe on %s\n", h.topic)
	if token := h.mqttClt.Subscribe(h.topic, 0, nil); token.Wait() && token.Error() != nil {
		return h.error("Failed to subscribe: %v", token.Error())
	}

	return h
}

func (h *handler) fatalIfErr() *handler {
	if h.err != nil {
		h.closeMqtt(250)
		log.Fatalf("%s\n", h.err)
	}

	return h
}

func (h *handler) waitMessages() *handler {
	if h.abort() || !h.isSubscribeAction() {
		return h
	}

	// TODO better wait with quit base on chan ?
	info("Wait messages...\n")
	time.Sleep(MaxDuration)
	return h
}

func process(endpoint string, port uint, cafile string, pkeyfile string, certfile string, clientid string, topic string, publish bool,
	websocket bool, awsregion string, awsaccesskey string, awssecretkey string) {

	hand := handler{
		topic:      topic,
		websocket:  websocket,
		awsRegion:  awsregion,
		mqttAction: If(publish, PublishAction, SubscribeAction),
	}

	defer hand.closeMqtt(250)
	hand.
		ctrlC().
		tlsConfig(cafile, pkeyfile, certfile).
		brokerUri(endpoint, port).
		cltOpts(clientid).
		connect().
		readStdin().
		publish().
		subscribe().
		fatalIfErr().
		waitMessages()
}

// TODO Implement proper log info
func info(format string, args ...any) {
	log.Printf(format, args...)
}

func If[T any](cond bool, vtrue, vfalse T) T {
	if cond {
		return vtrue
	}
	return vfalse
}

// Pre-register custom HTTP proxy dialers for use with proxy.FromEnvironment call by paho.mqtt.openConnection
func init() {
	proxy.RegisterDialerType("http", newHTTPProxy)
	proxy.RegisterDialerType("https", newHTTPProxy)
}

func main() {
	endpoint := flag.String("endpoint", "a2m9dujvq8fryc-ats.iot.eu-west-1.amazonaws.com", "endpoint to connect")
	port := flag.Uint("port", 8883, "aws iot supports 8883 for mqtt and 443 for mqtt over websocket")
	cafile := flag.String("ca_file", "", "path to the root certificate authority file in pem format to thrust")
	pkey := flag.String("pkey", "", "path to your private key file in pem format")
	cert := flag.String("cert", "", "path to your client certificate file in pem format")
	clientid := flag.String("client_id", "joule-pac-1", "client id to use when open mqtt connection")
	topic := flag.String("topic", "joule-pac-1/topic1", "topic to publish or subscribe filter to use")
	publish := flag.Bool("publish", false, "if true, use stdin to publish message")
	awsregion := flag.String("region", "eu-west-1", "aws region parameter when signV4 authentication")
	websocket := flag.Bool("websocket", false, "wrap mqtt into websocket")
	debug := flag.Bool("debug", false, "show mqtt connection debug messages")

	awsaccesskey := ""
	awssecretkey := ""

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s, version %s: \n", os.Args[0], version)
		flag.PrintDefaults()
	}

	flag.Parse()

	if *debug {
		mqtt.ERROR = log.New(os.Stdout, "[ERROR] ", 0)
		mqtt.CRITICAL = log.New(os.Stdout, "[CRIT] ", 0)
		mqtt.WARN = log.New(os.Stdout, "[WARN]  ", 0)
		mqtt.DEBUG = log.New(os.Stdout, "[DEBUG] ", 0)
	}

	// TODO Proper args check
	if *websocket {

		awsaccesskey = os.Getenv(AwsAccessKeyEnvVarName)
		awssecretkey = os.Getenv(AwsSecretKeyEnvVarName)

		if awsaccesskey == "" || awssecretkey == "" {
			fmt.Fprintf(os.Stderr, "%s and %s should be set in environment variables with websocket mode\n", AwsAccessKeyEnvVarName, AwsSecretKeyEnvVarName)
			os.Exit(1)
		}

		if *port == 8883 {
			fmt.Fprintf(os.Stdout, "Warning : you still used default port for mqtt over websocket !\n")
		}
	} else if *cafile == "" || *pkey == "" || *cert == "" {
		flag.Usage()
		os.Exit(1)
	}

	process(*endpoint, *port, *cafile, *pkey, *cert, *clientid, *topic, *publish, *websocket, *awsregion, awsaccesskey, awssecretkey)
}
