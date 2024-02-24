# cert-source

[![Release](https://img.shields.io/github/v/release/grepplabs/cert-source?sort=semver)](https://github.com/grepplabs/cert-source/releases)
![Build](https://github.com/grepplabs/cert-source/workflows/tests/badge.svg)

## Overview

The cert-source is a library designed to help with loading of TLS certificates and to streamline the process of
certificate rotation.


## Usage

### Installation

```bash
go get -u github.com/grepplabs/cert-source
```

### TLS server

```go
package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"time"

	tlsconfig "github.com/grepplabs/cert-source/config"
	tlsserverconfig "github.com/grepplabs/cert-source/tls/server/config"
)

func main() {
	tlsConfig, err := tlsserverconfig.GetServerTLSConfig(slog.Default(), &tlsconfig.TLSServerConfig{
		Enable:  true,
		Refresh: 1 * time.Second,
		File: tlsconfig.TLSServerFiles{
			Key:       "key.pem",
			Cert:      "cert.pem",
			ClientCAs: "",
			ClientCRL: "",
		},
	})
	if err != nil {
		log.Fatalln(err)
	}
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "Hello, TLS world!")
	})
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalln(err)
	}
}
```

### TLS Client

```go
package main

import (
	"io"
	"log"
	"log/slog"
	"net/http"
	"time"

	tlsconfig "github.com/grepplabs/cert-source/config"
	tlsclient "github.com/grepplabs/cert-source/tls/client"
	tlsclientconfig "github.com/grepplabs/cert-source/tls/client/config"
)

func main() {
	tlsClientConfigFunc, err := tlsclientconfig.GetTLSClientConfigFunc(slog.Default(), &tlsconfig.TLSClientConfig{
		Enable:             true,
		Refresh:            1 * time.Second,
		InsecureSkipVerify: false,
		File: tlsconfig.TLSClientFiles{
			Key:     "",
			Cert:    "",
			RootCAs: "ca.pem",
		},
	})
	if err != nil {
		log.Fatalln(err)
	}
	transport := tlsclient.NewDefaultRoundTripper(tlsclient.WithClientTLSConfig(tlsClientConfigFunc()))
	client := &http.Client{Transport: transport}
	resp, err := client.Get("https://localhost:8443")
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}
	log.Printf("Server response: %s", body)
}
```
