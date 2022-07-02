package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	// https://github.com/eclipse/paho.mqtt.golang
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"golang.org/x/net/proxy"
)

type handler struct {
	err         error
	config      *tls.Config
	mqttCltOpts *mqtt.ClientOptions
	mqttClt     mqtt.Client
	inputMsg    []byte
	websocket   bool
}

func (h *handler) abort() bool {
	return h.err != nil
}

func (h *handler) error(format string, a ...any) *handler {
	h.err = fmt.Errorf(format, a...)
	return h
}

func (h *handler) fatalIfErr() *handler {
	if h.err != nil {
		h.closeMqtt(250)
		log.Fatalf("%s\n", h.err)
	}

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

func (h *handler) tlsConfig(cafile string, pkeyfile string, certfile string) *handler {
	if h.abort() {
		return h
	}

	// https://www.emqx.com/en/blog/how-to-use-mqtt-in-golang
	// https://github.com/aws/aws-sdk-go/issues/820
	// https://github.com/seqsense/aws-iot-device-sdk-go/blob/master/dialer.go
	// https://docs.aws.amazon.com/sdk-for-go/api/aws/signer/v4/
	// https://github.com/aws/aws-sdk-go/blob/main/aws/signer/v4/v4.go
	if h.websocket {
		h.config = &tls.Config{
			// ClientAuth = whether to request cert from server.
			// Since the server is set up for SSL, this happens
			// anyways.
			ClientAuth: tls.NoClientCert,
			// ClientCAs = certs used to validate client cert.
			ClientCAs:          nil,
			InsecureSkipVerify: true,
		}
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

		// Create tls.Config with desired tls properties
		h.config = &tls.Config{
			// RootCAs = certs used to verify server cert.
			RootCAs: certpool,
			// ClientAuth = whether to request cert from server.
			// Since the server is set up for SSL, this happens
			// anyways.
			ClientAuth: tls.NoClientCert,
			// ClientCAs = certs used to validate client cert.
			ClientCAs: nil,
			// Certificates = list of certs client sends to server.
			Certificates: []tls.Certificate{cert},
		}
	}

	return h
}

func (h *handler) cltOpts(endpoint string, port uint, clientid string) *handler {
	if h.abort() {
		return h
	}

	protocol := If(h.websocket, "wss", "tls")

	h.mqttCltOpts = mqtt.NewClientOptions().
		AddBroker(fmt.Sprintf("%s://%s:%v", protocol, endpoint, port)).
		SetClientID(clientid).
		SetTLSConfig(h.config).
		SetDefaultPublishHandler(func(client mqtt.Client, msg mqtt.Message) {
			log.Printf("Received message on topic: %s\n", msg.Topic())
			fmt.Printf("%s\n", msg.Payload())
		})

	return h
}

func (h *handler) connect() *handler {
	if h.abort() {
		return h
	}

	info("Open mqtt\n")
	h.mqttClt = mqtt.NewClient(h.mqttCltOpts)
	if token := h.mqttClt.Connect(); token.Wait() && token.Error() != nil {
		h.error("Failed to create mqtt connection: %v", token.Error())
	}

	return h
}

func (h *handler) publish(topic string) *handler {
	if h.abort() {
		return h
	}

	info("Send message to %s\n", topic)
	if token := h.mqttClt.Publish(topic, 0, false, h.inputMsg); token.Wait() && token.Error() != nil {
		h.error("Failed to send message: %v", token.Error())
	}

	return h
}

// https://flaviocopes.com/go-shell-pipes/
func (h *handler) readStdin() *handler {
	if h.abort() {
		return h
	}

	stdInfo, err := os.Stdin.Stat()

	if err != nil {
		return h.error("Failed to read from stdin: %v", err)
	}

	// time.Sleep(time.Second * 30)
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

func (h *handler) subscribe(topic string) *handler {
	if h.abort() {
		return h
	}

	info("Subscribe on %s\n", topic)

	if token := h.mqttClt.Subscribe(topic, 0, nil); token.Wait() && token.Error() != nil {
		h.error("Failed to subscribe: %v", token.Error())
	}

	return h
}

// Gracefully shutdown on ctrl+c
// https://golangcode.com/handle-ctrl-c-exit-in-terminal/
func (h *handler) ctrlC() *handler {
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

// 292 years
const maxDuration time.Duration = 1<<63 - 1

func process(endpoint string, port uint, cafile string, pkeyfile string, certfile string, clientid string, topic string, publish bool,
	websocket bool, proxyhost string, proxyport uint, awsregion string, awsaccesskey string, awssecretkey string) {
	hand := handler{websocket: websocket}
	defer hand.closeMqtt(250)

	hand.
		ctrlC().
		tlsConfig(cafile, pkeyfile, certfile).
		cltOpts(endpoint, port, clientid).
		connect()

	if publish {
		hand.
			readStdin().
			publish(topic).
			fatalIfErr()
	} else {
		hand.
			subscribe(topic).
			fatalIfErr()

		// TODO better wait with quit base on chan ?
		info("Wait messages...\n")
		time.Sleep(maxDuration)
	}
}

// TODO Implement proper log info
func info(format string, args ...any) {
	log.Printf(format, args...)
}

func init() {
	// Pre-register custom HTTP proxy dialers for use with proxy.FromEnvironment
	proxy.RegisterDialerType("http", newHTTPProxy)
	proxy.RegisterDialerType("https", newHTTPProxy)
}

func If[T any](cond bool, vtrue, vfalse T) T {
	if cond {
		return vtrue
	}
	return vfalse
}

func main() {
	endpoint := flag.String("endpoint", "a2m9dujvq8fryc-ats.iot.eu-west-1.amazonaws.com", "endpoint to connect")
	port := flag.Uint("port", 8883, "aws iot supports 433 and 8883")
	cafile := flag.String("ca_file", "", "root certificate authority to thrust")
	pkey := flag.String("pkey", "", "path to your private key in pem format")
	cert := flag.String("cert", "", "path to your client certificate in pem format")
	clientid := flag.String("client_id", "joule-pac-1", "client id to use for mqtt connection")
	topic := flag.String("topic", "joule-pac-1/topic1", "topic to publish or topic filter to use")
	publish := flag.Bool("publish", false, "if true, use stdin to publish message")
	proxyhost := flag.String("proxy_host", "", "hostname of http proxy, if set use mqtt over websocket mode")
	proxyport := flag.Uint("proxy_port", 3131, "port of http proxy")
	awsregion := flag.String("region", "eu-west-1", "aws region parameter")
	websocket := flag.Bool("websocket", false, "use mqtt over websocket mode")
	debug := flag.Bool("debug", false, "show mqtt debug messages")

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

	awsaccesskey := ""
	awssecretkey := ""

	// TODO Proper args check
	if *proxyhost != "" {
		*websocket = true
	}

	if *websocket {
		awsaccesskey = os.Getenv("AWS_ACCESS_KEY_ID")
		awssecretkey = os.Getenv("AWS_SECRET_ACCESS_KEY")

		if awsaccesskey == "" || awssecretkey == "" {
			fmt.Fprintf(os.Stderr, "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY should be set in env variables with proxy/websocket mode\n")
			os.Exit(1)
		}
	}

	if !*websocket && (*cafile == "" || *pkey == "" || *cert == "") {
		flag.Usage()
		os.Exit(1)
	}

	process(*endpoint, *port, *cafile, *pkey, *cert, *clientid, *topic, *publish, *websocket, *proxyhost, *proxyport, *awsregion, awsaccesskey, awssecretkey)
}
