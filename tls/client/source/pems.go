package source

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

type ClientPEMsLoader interface {
	Load() (*ClientPEMs, error)
}

type ClientPEMs struct {
	CertPEMBlock    []byte
	KeyPEMBlock     []byte
	RootCAsPEMBlock []byte
}

func (s ClientPEMs) Checksum() []byte {
	hash := sha256.New()
	hash.Write(s.CertPEMBlock)
	hash.Write(s.KeyPEMBlock)
	return hash.Sum(s.RootCAsPEMBlock)
}

func (s ClientPEMs) Certificate() (*tls.Certificate, error) {
	if len(s.CertPEMBlock) == 0 || len(s.KeyPEMBlock) == 0 {
		return nil, nil
	}
	cert, err := tls.X509KeyPair(s.CertPEMBlock, s.KeyPEMBlock)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (s ClientPEMs) RootCAs() (*x509.CertPool, error) {
	if len(s.RootCAsPEMBlock) == 0 {
		return nil, nil
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(s.RootCAsPEMBlock) {
		return nil, errors.New("client PEMs: building client CAs failed")
	}
	return certPool, nil
}
