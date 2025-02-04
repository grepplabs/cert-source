package filesource

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
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

	clientCertsStore, err := tlsclient.NewTLSClientCertsStore(slog.Default(), clientSource)
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
		Transport: tlsclient.NewDefaultRoundTripper(tlsclient.WithClientCertsStore(clientCertsStore)),
	}
	_, err = client.Do(req)
	require.NoError(t, err)

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
		Transport: tlsclient.NewDefaultRoundTripper(tlsclient.WithClientCertsStore(clientCertsStore)),
	}
	_, err = client.Do(req)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "unknown certificate authority")

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

	clientCertsStore, err := tlsclient.NewTLSClientCertsStore(slog.Default(), clientSource)
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
		Transport: tlsclient.NewDefaultRoundTripper(tlsclient.WithClientCertsStore(clientCertsStore)),
	}
	_, err = client.Do(req)
	require.NoError(t, err)

}
