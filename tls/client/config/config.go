package config

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/grepplabs/cert-source/config"
	tlsclient "github.com/grepplabs/cert-source/tls/client"
	"github.com/grepplabs/cert-source/tls/client/filesource"
)

func GetTLSClientConfig(logger *slog.Logger, conf *config.TLSClientConfig, opts ...tlsclient.TLSClientConfigOption) (*tls.Config, error) {
	if !conf.Enable {
		return nil, nil
	}
	fs, err := filesource.New(
		filesource.WithLogger(logger.With("tls", "client")),
		filesource.WithRefresh(conf.Refresh),
		filesource.WithInsecureSkipVerify(conf.InsecureSkipVerify),
		filesource.WithClientCert(conf.File.Cert, conf.File.Key),
		filesource.WithClientRootCAs(conf.File.RootCAs),
		filesource.WithKeyPassword(conf.KeyPassword),
		filesource.WithSystemPool(conf.UseSystemPool),
	)
	if err != nil {
		return nil, fmt.Errorf("setup client cert file source: %w", err)
	}
	return tlsclient.NewTLSConfig(logger, fs, opts...)
}

func NewRoundTripper(logger *slog.Logger, conf *config.TLSClientConfig, opts ...tlsclient.TLSClientConfigOption) (*tlsclient.RoundTripper, error) {
	tlsConfig, err := GetTLSClientConfig(logger, conf, opts...)
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		return tlsclient.NewDefaultRoundTripper(), nil
	}
	return tlsclient.NewDefaultRoundTripper(tlsclient.WithClientTLSConfig(tlsConfig)), nil
}

func NewClient(logger *slog.Logger, conf *config.TLSClientConfig, opts ...tlsclient.TLSClientConfigOption) (*http.Client, error) {
	transport, err := NewRoundTripper(logger, conf, opts...)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: transport}, nil
}
