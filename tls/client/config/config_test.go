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
	tlsConfigFunc, err := GetTLSClientConfigFunc(slog.Default(), &config.TLSClientConfig{
		Enable:  true,
		Refresh: 0,
		File: config.TLSClientFiles{
			Key:     bundle.ClientKey.Name(),
			Cert:    bundle.ClientCert.Name(),
			RootCAs: bundle.CACert.Name(),
		},
	}, tlsclient.WithTLSClientNextProtos([]string{"h2"}))
	require.NoError(t, err)
	tlsConfig := tlsConfigFunc()
	require.NotNil(t, tlsConfig.RootCAs)
	require.Equal(t, tlsConfig.NextProtos, []string{"h2"})

	clientCert, err := tlsConfig.GetClientCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, clientCert)
}
