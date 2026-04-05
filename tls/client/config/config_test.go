package config

import (
	"log/slog"
	"testing"

	"github.com/grepplabs/cert-source/config"
	"github.com/grepplabs/cert-source/internal/testutil"
	tlsclient "github.com/grepplabs/cert-source/tls/client"
	"github.com/stretchr/testify/require"
)

func TestGetClientTLSConfig(t *testing.T) {
	bundle := testutil.NewCertsBundle()
	defer bundle.Close()
	tlsConfig, err := GetTLSClientConfig(slog.Default(), &config.TLSClientConfig{
		Enable:  true,
		Refresh: 0,
		File: config.TLSClientFiles{
			Key:     bundle.ClientKey.Name(),
			Cert:    bundle.ClientCert.Name(),
			RootCAs: bundle.CACert.Name(),
		},
	}, tlsclient.WithTLSClientHTTP2(), tlsclient.WithTLSServerName("localhost"))
	require.NoError(t, err)
	require.True(t, tlsConfig.InsecureSkipVerify)
	require.NotNil(t, tlsConfig.VerifyConnection)
	require.Equal(t, []string{"h2"}, tlsConfig.NextProtos)
	require.Equal(t, "localhost", tlsConfig.ServerName)

	clientCert, err := tlsConfig.GetClientCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, clientCert)
}

func TestGetClientTLSConfigNoConfig(t *testing.T) {
	bundle := testutil.NewCertsBundle()
	defer bundle.Close()
	tlsConfig, err := GetTLSClientConfig(slog.Default(), &config.TLSClientConfig{
		Enable:  true,
		Refresh: 0,
		File:    config.TLSClientFiles{},
	})
	require.NoError(t, err)
	require.True(t, tlsConfig.InsecureSkipVerify)
	require.Nil(t, tlsConfig.GetClientCertificate)
}

func TestGetClientTLSConfigSkipVerify(t *testing.T) {
	bundle := testutil.NewCertsBundle()
	defer bundle.Close()
	tlsConfig, err := GetTLSClientConfig(slog.Default(), &config.TLSClientConfig{
		Enable:             true,
		Refresh:            0,
		InsecureSkipVerify: true,
		File: config.TLSClientFiles{
			Key:  bundle.ClientKey.Name(),
			Cert: bundle.ClientCert.Name(),
		},
	})
	require.NoError(t, err)
	require.True(t, tlsConfig.InsecureSkipVerify)

	clientCert, err := tlsConfig.GetClientCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, clientCert)
}

func TestGetClientTLSHTTP2AndHTTP11Config(t *testing.T) {
	bundle := testutil.NewCertsBundle()
	defer bundle.Close()

	tlsConfig, err := GetTLSClientConfig(slog.Default(), &config.TLSClientConfig{
		Enable:  true,
		Refresh: 0,
		File: config.TLSClientFiles{
			Key:     bundle.ClientKey.Name(),
			Cert:    bundle.ClientCert.Name(),
			RootCAs: bundle.CACert.Name(),
		},
	}, tlsclient.WithTLSClientHTTP2AndHTTP11())
	require.NoError(t, err)
	require.Equal(t, []string{"h2", "http/1.1"}, tlsConfig.NextProtos)
}
