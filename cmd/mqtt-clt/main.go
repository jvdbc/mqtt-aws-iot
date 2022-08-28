package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"golang.org/x/net/proxy"
)

const (
	AwsAccessKeyEnvVarName = "AWS_ACCESS_KEY_ID"
	AwsSecretKeyEnvVarName = "AWS_SECRET_ACCESS_KEY"
)

var (
	InfoLog = log.New(os.Stdout, "[INFO] ", log.LstdFlags)
)

func start(endpoint string, port uint, cafile string, keyfile string, certfile string, clientid string, topic string, publish bool,
	websocket bool, awsregion string, awsaccesskey string, awssecretkey string) {

	client := New(endpoint, port, clientid)
	defer client.CloseMqtt(250)

	switch websocket {
	case true:
		fatalIfErr(client.ConnectWS(awsregion))
	default:
		fatalIfErr(client.Connect(cafile, keyfile, certfile))
	}

	switch publish {
	case true:
		inputMsg, err := readStdin()
		fatalIfErr(err)
		fatalIfErr(client.Publish(topic, inputMsg))
	default:
		fatalIfErr(client.Subscribe(topic))
		wait()
	}
}

func info(format string, args ...any) {
	InfoLog.Printf(format, args...)
}

// Pre-register custom HTTP proxy dialers for use with proxy.FromEnvironment call by paho.mqtt.openConnection
func init() {
	proxy.RegisterDialerType("http", newHTTPProxy)
	proxy.RegisterDialerType("https", newHTTPProxy)
}

func wait() {
	// TODO better wait with quit base on chan ?
	info("wait messages...\n")
	time.Sleep(MaxDuration)
}

// https://flaviocopes.com/go-shell-pipes/
func readStdin() ([]byte, error) {
	stdInfo, err := os.Stdin.Stat()

	if err != nil {
		return nil, fmt.Errorf("failed to read from stdin: %w", err)
	}

	if (stdInfo.Mode() & os.ModeCharDevice) != 0 {
		return nil, errors.New("publish is intended to work with input pipe message")
	}

	var lines []byte
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		lines = append(lines, scanner.Bytes()...)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read input message %w", err)
	}

	return lines, nil
}

func fatalIfErr(args ...interface{}) {
	for _, arg := range args {
		switch err := arg.(type) {
		case error:
			log.Fatalf("%s\n", err)
		}
	}
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
			fmt.Fprintf(os.Stdout, "warning : you still used default port for mqtt over websocket !\n")
		}
	} else if *cafile == "" || *pkey == "" || *cert == "" {
		flag.Usage()
		os.Exit(1)
	}

	start(*endpoint, *port, *cafile, *pkey, *cert, *clientid, *topic, *publish, *websocket, *awsregion, awsaccesskey, awssecretkey)
}
