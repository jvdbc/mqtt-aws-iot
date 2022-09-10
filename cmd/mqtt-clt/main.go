package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/urfave/cli/v2"
	"golang.org/x/net/proxy"
)

const (
	AwsAccessKeyEnvVarName = "AWS_ACCESS_KEY_ID"
	AwsSecretKeyEnvVarName = "AWS_SECRET_ACCESS_KEY"

	EndpointFlag  = "endpoint"
	PortFlag      = "port"
	CafileFlag    = "ca_file"
	PkeyFlag      = "pkey"
	CertFlag      = "cert"
	ClientidFlag  = "client_id"
	TopicFlag     = "topic"
	PublishFlag   = "publish"
	RegionFlag    = "region"
	WebsocketFlag = "websocket"
	DebugFlag     = "debug"
)

var (
	InfoLog  = log.New(os.Stdout, "[INFO] ", log.LstdFlags)
	ErrorLog = log.New(os.Stderr, "[ERROR] ", log.LstdFlags)
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

func infof(format string, args ...any) {
	InfoLog.Printf(format, args...)
}

func errorf(format string, args ...any) {
	ErrorLog.Printf(format, args...)
}

func wait() {
	// TODO better wait with quit base on chan ?
	infof("wait messages...\n")
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
			errorf("%s\n", err)
			os.Exit(1)
		}
	}
}

// Pre-register custom HTTP proxy dialers for use with proxy.FromEnvironment call by paho.mqtt.openConnection
func init() {
	proxy.RegisterDialerType("http", newHTTPProxy)
	proxy.RegisterDialerType("https", newHTTPProxy)
}

func main() {
	app := &cli.App{
		Name:    os.Args[0],
		Version: version,
		Usage:   "subscribe, publish to aws iot-core devices-gateway",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  EndpointFlag,
				Value: "a2m9dujvq8fryc-ats.iot.eu-west-1.amazonaws.com",
				Usage: "endpoint to connect",
			},
			&cli.UintFlag{
				Name:  PortFlag,
				Value: 8883,
				Usage: "aws iot supports 8883 for mqtt and 443 for mqtt over websocket",
			},
			&cli.StringFlag{
				Name:  ClientidFlag,
				Value: "joule-pac-1",
				Usage: "client id to use when open mqtt connection",
			},
			&cli.StringFlag{
				Name:  TopicFlag,
				Value: "joule-pac-1/topic1",
				Usage: "topic to publish or subscribe filter to use",
			},
			&cli.BoolFlag{
				Name:  PublishFlag,
				Value: false,
				Usage: "if true, use stdin to publish message",
			},
			&cli.StringFlag{
				Name:  CafileFlag,
				Value: "",
				Usage: "path to the root certificate authority file in pem format to thrust",
			},
			&cli.StringFlag{
				Name:  PkeyFlag,
				Value: "",
				Usage: "path to your private key file in pem format",
			},
			&cli.StringFlag{
				Name:  CertFlag,
				Value: "",
				Usage: "path to your client certificate file in pem format",
			},
			&cli.StringFlag{
				Name:  RegionFlag,
				Value: "eu-west-1",
				Usage: "aws region parameter when signV4 authentication",
			},
			&cli.BoolFlag{
				Name:  WebsocketFlag,
				Value: false,
				Usage: "if true, wrap mqtt into websocket",
			},
			&cli.BoolFlag{
				Name:  DebugFlag,
				Value: false,
				Usage: "if true, show mqtt connection debug messages",
			},
		},
		Action: func(ctx *cli.Context) error {

			if ctx.Bool(DebugFlag) {
				mqtt.ERROR = ErrorLog
				mqtt.CRITICAL = log.New(os.Stdout, "[CRIT] ", 0)
				mqtt.WARN = log.New(os.Stdout, "[WARN]  ", 0)
				mqtt.DEBUG = log.New(os.Stdout, "[DEBUG] ", 0)
			}

			awsaccesskey := ""
			awssecretkey := ""

			if ctx.Bool(WebsocketFlag) {
				awsaccesskey = os.Getenv(AwsAccessKeyEnvVarName)
				awssecretkey = os.Getenv(AwsSecretKeyEnvVarName)

				if awsaccesskey == "" || awssecretkey == "" {
					return fmt.Errorf("%s and %s should be set in environment variables with websocket mode", AwsAccessKeyEnvVarName, AwsSecretKeyEnvVarName)
				}

				if ctx.Uint(PortFlag) == 8883 {
					fmt.Println("warning : you still used default port for mqtt over websocket !")
				}
			} else if ctx.String(CafileFlag) == "" || ctx.String(PkeyFlag) == "" || ctx.String(CertFlag) == "" {
				return fmt.Errorf("%s, %s and %s should not be empty in mqtt mode", CafileFlag, PkeyFlag, CertFlag)
			}

			start(
				ctx.String(EndpointFlag), ctx.Uint(PortFlag),
				ctx.String(CafileFlag), ctx.String(PkeyFlag), ctx.String(CertFlag),
				ctx.String(ClientidFlag),
				ctx.String(TopicFlag),
				ctx.Bool(PublishFlag),
				ctx.Bool(WebsocketFlag),
				ctx.String(RegionFlag),
				awsaccesskey, awssecretkey)

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		errorf("%s\n", err)
		os.Exit(1)
	}
}
