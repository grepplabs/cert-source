package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	})
	require.NoError(t, err)
	require.NotNil(t, tlsConfig.ClientCAs)
	systemPool, err := x509.SystemCertPool()
	require.NoError(t, err)
	// not system pool
	require.False(t, tlsConfig.ClientCAs.Equal(systemPool))
	require.Equal(t, tlsConfig.ClientAuth, tls.RequireAndVerifyClientCert)
	require.NotEmpty(t, tlsConfig.Certificates)
	// clientCRL verification
	require.NotNil(t, tlsConfig.VerifyPeerCertificate)
	require.Nil(t, tlsConfig.NextProtos)
	require.Nil(t, tlsConfig.CipherSuites)
	require.Nil(t, tlsConfig.CurvePreferences)
}

func TestGetServerTLSOptionsConfig(t *testing.T) {
	bundle := testutil.NewCertsBundle()
	defer bundle.Close()

	tlsConfig, err := GetServerTLSConfig(slog.Default(), &config.TLSServerConfig{
		Enable:  true,
		Refresh: 0,
		File: config.TLSServerFiles{
			Key:  bundle.ServerKey.Name(),
			Cert: bundle.ServerCert.Name(),
		},
	}, tlsserver.WithTLSServerNextProtos([]string{"h2"}),
		tlsserver.WithTLSServerCipherSuites([]uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}),
		tlsserver.WithTLSServerCurvePreferences([]tls.CurveID{tls.CurveP256, tls.CurveP384}),
	)
	require.NoError(t, err)
	require.Nil(t, tlsConfig.ClientCAs)
	require.Equal(t, tlsConfig.ClientAuth, tls.NoClientCert)
	require.NotEmpty(t, tlsConfig.Certificates)
	require.Nil(t, tlsConfig.VerifyPeerCertificate)
	require.Equal(t, tlsConfig.NextProtos, []string{"h2"})
	require.Equal(t, tlsConfig.CipherSuites, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256})
	require.Equal(t, tlsConfig.CurvePreferences, []tls.CurveID{tls.CurveP256, tls.CurveP384})
}

func TestGetServerTLSVerifyPeerCertificateConfig(t *testing.T) {
	bundle := testutil.NewCertsBundle()
	defer bundle.Close()

	tests := []struct {
		name        string
		clientCAs   string
		verifyFuncs []tlsserver.VerifyPeerCertificateFunc
		verifyError error
	}{
		{
			name: "no peer verification",
		},
		{
			name:        "default client CA/CLR verification",
			clientCAs:   bundle.CACert.Name(),
			verifyError: nil, // CRLs are not set, verification is successful
		},
		{
			name:      "client CA/CLR verify success, second verify success",
			clientCAs: bundle.CACert.Name(),
			verifyFuncs: []tlsserver.VerifyPeerCertificateFunc{
				func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return nil
				},
			},
		},
		{
			name:      "client CA/CLR verify success, third verify success",
			clientCAs: bundle.CACert.Name(),
			verifyFuncs: []tlsserver.VerifyPeerCertificateFunc{
				func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return nil
				},
				func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return nil
				},
			},
		},
		{
			name:      "client CA/CLR verify success, third verify failure",
			clientCAs: bundle.CACert.Name(),
			verifyFuncs: []tlsserver.VerifyPeerCertificateFunc{
				func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return nil
				},
				func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return errors.New("3 function failed")
				},
			},
			verifyError: errors.New("3 function failed"),
		},
		{
			name:      "client CA/CLR verify success, second verify failure",
			clientCAs: bundle.CACert.Name(),
			verifyFuncs: []tlsserver.VerifyPeerCertificateFunc{
				func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return errors.New("2 function failed")
				},
				func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return errors.New("3 function would also fail")
				},
			},
			verifyError: errors.New("2 function failed"),
		},
		{
			name: "first verify success",
			verifyFuncs: []tlsserver.VerifyPeerCertificateFunc{
				func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return nil
				},
			},
		},
		{
			name: "second verify success",
			verifyFuncs: []tlsserver.VerifyPeerCertificateFunc{
				func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return nil
				},
				func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return nil
				},
			},
		},
		{
			name: "second verify failure",
			verifyFuncs: []tlsserver.VerifyPeerCertificateFunc{
				func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return nil
				},
				func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return errors.New("2 function failed")
				},
			},
			verifyError: errors.New("2 function failed"),
		},
		{
			name: "first verify failure",
			verifyFuncs: []tlsserver.VerifyPeerCertificateFunc{
				func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return errors.New("1 function failed")
				},
				func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return errors.New("2 function would also fail")
				},
			},
			verifyError: errors.New("1 function failed"),
		},
		{
			name: "unset verify function",
			verifyFuncs: []tlsserver.VerifyPeerCertificateFunc{
				func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return errors.New("1 function failed")
				},
				nil, // unset chain of verify functions
				func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return nil
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			opts := make([]tlsserver.TLSServerConfigOption, 0, len(tc.verifyFuncs))
			for _, f := range tc.verifyFuncs {
				opts = append(opts, tlsserver.WithTLSServerVerifyPeerCertificate(f))
			}
			tlsConfig, err := GetServerTLSConfig(slog.Default(), &config.TLSServerConfig{
				Enable:  true,
				Refresh: 0,
				File: config.TLSServerFiles{
					Key:       bundle.ServerKey.Name(),
					Cert:      bundle.ServerCert.Name(),
					ClientCAs: tc.clientCAs,
				},
			}, opts...)
			require.NoError(t, err)
			if tc.clientCAs == "" && len(tc.verifyFuncs) == 0 {
				require.Nil(t, tlsConfig.VerifyPeerCertificate)
			} else {
				require.NotNil(t, tlsConfig.VerifyPeerCertificate)
				err = tlsConfig.VerifyPeerCertificate(nil, nil)
				require.Equal(t, tc.verifyError, err)
			}
		})
	}
}
