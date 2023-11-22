package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if len(os.Args) < 2 {
		fmt.Println("Usage: server <cert.pem> <key.pem>")
		os.Exit(1)
	}
	certFile := os.Args[1]
	//keyFile := os.Args[2]

	keyLogFile := flag.String("keylog", "", "key log file")
	flag.Parse()

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	certData, err := os.ReadFile(certFile)
	if err != nil {
		log.Fatal(err)
	}
	ok := pool.AppendCertsFromPEM(certData)
	if !ok {
		log.Fatal("failed to parse root certificate")
	}

	var qconf quic.Config
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: false,
			KeyLogWriter:       keyLog,
		},
		QuicConfig: &qconf,
	}
	defer roundTripper.Close()
	hclient := &http.Client{
		Transport: roundTripper,
	}

	addr := "https://localhost:6121"
	fmt.Printf("GET %s\n", addr)
	rsp, err := hclient.Get(addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Got response for %s: %#v", addr, rsp)

	body := &bytes.Buffer{}
	_, err = io.Copy(body, rsp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Response Body:")
	fmt.Printf("%s", body.Bytes())

	return nil
}
