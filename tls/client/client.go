package tlsclient

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"time"

	"github.com/grepplabs/cert-source/tls/client/source"
)

const (
	initLoadTimeout = 5 * time.Second
)

type TLSClientConfigFunc func() *tls.Config

func NewTLSClientConfigFunc(logger *slog.Logger, src source.ClientCertsSource, opts ...TLSClientConfigOption) (TLSClientConfigFunc, error) {
	store, err := NewTLSClientCertsStore(logger, src)
	if err != nil {
		return nil, err
	}
	return func() *tls.Config {
		cs := store.LoadClientCerts()
		x := &tls.Config{
			RootCAs:            cs.RootCAs,
			InsecureSkipVerify: cs.InsecureSkipVerify,
			GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return store.LoadClientCerts().Certificate, nil
			},
		}
		for _, opt := range opts {
			opt(x)
		}
		return x
	}, nil
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
