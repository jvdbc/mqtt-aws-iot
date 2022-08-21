package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"golang.org/x/net/proxy"
)

const (
	AwsAccessKeyEnvVarName = "AWS_ACCESS_KEY_ID"
	AwsSecretKeyEnvVarName = "AWS_SECRET_ACCESS_KEY"
)

func start(endpoint string, port uint, cafile string, keyfile string, certfile string, clientid string, topic string, publish bool,
	websocket bool, awsregion string, awsaccesskey string, awssecretkey string) {

	client := New(endpoint, port, topic, clientid, websocket, awsregion, publish)
	defer client.CloseMqtt(250)

	client.
		Config(cafile, keyfile, certfile).
		connect().
		publish().
		subscribe().
		fatalIfErr().
		waitMessages()
}

// TODO Implement proper log info
func info(format string, args ...any) {
	log.Printf(format, args...)
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

	start(*endpoint, *port, *cafile, *pkey, *cert, *clientid, *topic, *publish, *websocket, *awsregion, awsaccesskey, awssecretkey)
}
