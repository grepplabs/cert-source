package tlsclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"time"

	"github.com/grepplabs/cert-source/tls/client/source"
)

const (
	initLoadTimeout = 5 * time.Second
)

type Provider struct {
	store *source.ClientCertsStore
	opts  []TLSClientConfigOption
}

func NewProvider(logger *slog.Logger, src source.ClientCertsSource, opts ...TLSClientConfigOption) (*Provider, error) {
	store, err := NewTLSClientCertsStore(logger, src)
	if err != nil {
		return nil, err
	}
	return &Provider{
		store: store,
		opts:  opts,
	}, nil
}

func (p *Provider) LoadClientCerts() source.ClientCerts {
	return p.store.LoadClientCerts()
}

func (p *Provider) TLSConfig() *tls.Config {
	cs := p.LoadClientCerts()
	x := &tls.Config{
		// Root CAs are read dynamically in VerifyConnection to support rotation.
		// nolint:gosec
		InsecureSkipVerify: true,
	}
	var getClientCertificateFunc func(info *tls.CertificateRequestInfo) (*tls.Certificate, error)
	if cs.Certificate != nil {
		// Set function only when client certificate is available.
		// TLS 1.3 checks if GetClientCertificate function is nil, if it is not nil,
		// it assumes client certificate is available which call cause the panic if nil is returned.
		//nolint:unparam
		getClientCertificateFunc = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return p.LoadClientCerts().Certificate, nil
		}
	}
	x.GetClientCertificate = getClientCertificateFunc
	for _, opt := range p.opts {
		opt(x)
	}
	x.VerifyConnection = p.verifyConnection(x.ServerName)
	return x
}

func (p *Provider) verifyConnection(configuredServerName string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		clientCerts := p.LoadClientCerts()
		if clientCerts.InsecureSkipVerify {
			return nil
		}
		if len(cs.PeerCertificates) == 0 {
			return errors.New("tls: no peer certificates")
		}

		serverName := cs.ServerName
		if serverName == "" {
			serverName = configuredServerName
		}

		opts := x509.VerifyOptions{
			Roots:         clientCerts.RootCAs,
			DNSName:       serverName,
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, err := cs.PeerCertificates[0].Verify(opts)
		return err
	}
}

func NewTLSConfig(logger *slog.Logger, src source.ClientCertsSource, opts ...TLSClientConfigOption) (*tls.Config, error) {
	provider, err := NewProvider(logger, src, opts...)
	if err != nil {
		return nil, err
	}
	return provider.TLSConfig(), nil
}

func NewTLSClientCertsStore(logger *slog.Logger, src source.ClientCertsSource) (*source.ClientCertsStore, error) {
	store := source.NewClientCertsStore(logger)
	logger.Info("initial client certs loading")

	certsChan := src.ClientCerts()

	select {
	case certs := <-certsChan:
		store.SetClientCerts(certs)
	case <-time.After(initLoadTimeout):
		return nil, errors.New("get client certs timeout")
	}

	go func() {
		for certs := range certsChan {
			store.SetClientCerts(certs)
		}
	}()
	return store, nil
}
