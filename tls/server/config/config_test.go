package config

import (
	"crypto/tls"
	"log/slog"
	"testing"

	"github.com/grepplabs/cert-source/config"
	"github.com/grepplabs/cert-source/internal/testutil"
	tlsserver "github.com/grepplabs/cert-source/tls/server"
	"github.com/stretchr/testify/require"
)

func TestGetServerTLSConfig(t *testing.T) {
	bundle := testutil.NewCertsBundle()
	defer bundle.Close()

	tlsConfig, err := GetServerTLSConfig(slog.Default(), &config.TLSServerConfig{
		Enable:  true,
		Refresh: 0,
		File: config.TLSServerFiles{
			Key:       bundle.ServerKey.Name(),
			Cert:      bundle.ServerCert.Name(),
			ClientCAs: bundle.CACert.Name(),
			ClientCRL: bundle.ClientCRL.Name(),
		},
	}, tlsserver.WithTLSServerNextProtos([]string{"h2"}))
	require.NoError(t, err)
	require.NotNil(t, tlsConfig.ClientCAs)
	require.Equal(t, tlsConfig.ClientAuth, tls.RequireAndVerifyClientCert)
	require.NotEmpty(t, tlsConfig.Certificates)
	require.NotNil(t, tlsConfig.VerifyPeerCertificate)
	require.Equal(t, tlsConfig.NextProtos, []string{"h2"})
}
