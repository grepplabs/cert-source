package filesource

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grepplabs/cert-source/internal/testutil"
	tlsclient "github.com/grepplabs/cert-source/tls/client"
	servertls "github.com/grepplabs/cert-source/tls/server"
	serverfilesource "github.com/grepplabs/cert-source/tls/server/filesource"
	"github.com/stretchr/testify/require"
)

func TestCertRotation(t *testing.T) {
	bundle1 := testutil.NewCertsBundle()
	defer bundle1.Close()

	bundle2 := testutil.NewCertsBundle()
	defer bundle2.Close()

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	rotatedCh := make(chan struct{}, 1)
	notifyFunc := func() {
		rotatedCh <- struct{}{}
	}
	clientSource := MustNew(
		WithClientRootCAs(bundle1.CACert.Name()),
		WithClientCert(bundle1.ClientCert.Name(), bundle1.ClientKey.Name()),
		WithRefresh(1*time.Second),
		WithNotifyFunc(notifyFunc),
	).(*fileSource)

	tlsConfig, err := tlsclient.NewTLSConfig(slog.Default(), clientSource)
	require.NoError(t, err)

	serverSource := serverfilesource.MustNew(
		serverfilesource.WithX509KeyPair(bundle1.ServerCert.Name(), bundle1.ServerKey.Name()),
		serverfilesource.WithClientAuthFile(bundle1.CACert.Name()),
		serverfilesource.WithClientCRLFile(bundle1.CAEmptyCRL.Name()),
		serverfilesource.WithRefresh(1*time.Second),
		serverfilesource.WithNotifyFunc(notifyFunc),
	)
	ts.TLS = servertls.MustNewServerConfig(slog.Default(), serverSource)
	ts.StartTLS()

	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	require.NoError(t, err)

	// when
	client := &http.Client{
		Transport: tlsclient.NewDefaultRoundTripper(tlsclient.WithClientTLSConfig(tlsConfig)),
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.NoError(t, os.Rename(bundle2.ClientCert.Name(), bundle1.ClientCert.Name()))
	require.NoError(t, os.Rename(bundle2.ClientKey.Name(), bundle1.ClientKey.Name()))

	select {
	case <-rotatedCh:
		t.Log("certificates were changed")
		time.Sleep(100 * time.Millisecond)
	case <-time.After(3 * time.Second):
		t.Fatal("expected certificate change notification")
	}

	// old client - bad certificate
	// create new client as connection can be kept alive
	client = &http.Client{
		Transport: tlsclient.NewDefaultRoundTripper(tlsclient.WithClientTLSConfig(tlsConfig)),
	}
	// nolint:bodyclose
	_, err = client.Do(req)
	require.Error(t, err)

	msg := err.Error()
	ok := strings.Contains(msg, "unknown certificate authority") ||
		strings.Contains(msg, `possibly because of "crypto/rsa: verification error" while trying to verify candidate authority certificate "ca-cert"`)
	require.Truef(t, ok, "unexpected error: %q", msg)
}

func TestKeyEncryption(t *testing.T) {
	bundle := testutil.NewCertsBundle()
	defer bundle.Close()

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	clientSource := MustNew(
		WithClientRootCAs(bundle.CACert.Name()),
		WithClientCert(bundle.ClientCert.Name(), bundle.ClientKeyEncrypted.Name()),
		WithKeyPassword(bundle.ClientKeyPassword),
		WithRefresh(1*time.Second),
		WithSystemPool(true),
	).(*fileSource)

	tlsConfig, err := tlsclient.NewTLSConfig(slog.Default(), clientSource)
	require.NoError(t, err)

	serverSource := serverfilesource.MustNew(
		serverfilesource.WithX509KeyPair(bundle.ServerCert.Name(), bundle.ServerKeyEncrypted.Name()),
		serverfilesource.WithKeyPassword(bundle.ServerKeyPassword),
		serverfilesource.WithClientAuthFile(bundle.CACert.Name()),
		serverfilesource.WithClientCRLFile(bundle.CAEmptyCRL.Name()),
		serverfilesource.WithRefresh(1*time.Second),
	)
	ts.TLS = servertls.MustNewServerConfig(slog.Default(), serverSource)
	ts.StartTLS()

	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	require.NoError(t, err)

	// when
	client := &http.Client{
		Transport: tlsclient.NewDefaultRoundTripper(tlsclient.WithClientTLSConfig(tlsConfig)),
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
}

func TestTLSConfigRotatesRootCAs(t *testing.T) {
	bundle1 := testutil.NewCertsBundle()
	defer bundle1.Close()

	bundle2 := testutil.NewCertsBundle()
	defer bundle2.Close()

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	rotatedCh := make(chan struct{}, 1)
	notifyFunc := func() {
		rotatedCh <- struct{}{}
	}
	clientSource := MustNew(
		WithClientRootCAs(bundle1.CACert.Name()),
		WithClientCert(bundle1.ClientCert.Name(), bundle1.ClientKey.Name()),
		WithRefresh(1*time.Second),
		WithNotifyFunc(notifyFunc),
	)

	serverSource := serverfilesource.MustNew(
		serverfilesource.WithX509KeyPair(bundle1.ServerCert.Name(), bundle1.ServerKey.Name()),
		serverfilesource.WithClientAuthFile(bundle1.CACert.Name()),
		serverfilesource.WithClientCRLFile(bundle1.CAEmptyCRL.Name()),
		serverfilesource.WithRefresh(1*time.Second),
	)
	ts.TLS = servertls.MustNewServerConfig(slog.Default(), serverSource)
	ts.StartTLS()

	tlsConfig, err := tlsclient.NewTLSConfig(slog.Default(), clientSource)
	require.NoError(t, err)

	client := &http.Client{
		Transport: tlsclient.NewDefaultRoundTripper(tlsclient.WithClientTLSConfig(tlsConfig)),
	}
	resp, err := client.Get(ts.URL)
	require.NoError(t, err)
	resp.Body.Close()

	require.NoError(t, os.Rename(bundle2.CACert.Name(), bundle1.CACert.Name()))

	select {
	case <-rotatedCh:
		time.Sleep(100 * time.Millisecond)
	case <-time.After(3 * time.Second):
		t.Fatal("expected certificate change notification")
	}

	client = &http.Client{
		Transport: tlsclient.NewDefaultRoundTripper(tlsclient.WithClientTLSConfig(tlsConfig)),
	}
	resp, err = client.Get(ts.URL)
	if resp != nil {
		resp.Body.Close()
	}
	require.Error(t, err)

	msg := err.Error()
	ok := strings.Contains(msg, "certificate signed by unknown authority") ||
		strings.Contains(msg, "unknown certificate authority")
	require.Truef(t, ok, "unexpected error: %q", msg)
}
