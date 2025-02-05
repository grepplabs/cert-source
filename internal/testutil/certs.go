package testutil

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"reflect"
	"time"

	tlsclient "github.com/grepplabs/cert-source/tls/client"
	"github.com/grepplabs/cert-source/tls/keyutil"
)

const DefaultKeyPassword = "test123"

func GenerateCRL(caX509Cert *x509.Certificate, caPrivateKey crypto.PrivateKey, certs []*x509.Certificate, crlFile *os.File) error {
	revoked := make([]x509.RevocationListEntry, 0)
	for _, cert := range certs {
		revoked = append(revoked, x509.RevocationListEntry{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: time.Now().Add(-1 * time.Minute),
		})
	}
	template := &x509.RevocationList{
		SignatureAlgorithm:        x509.SHA256WithRSA,
		RevokedCertificateEntries: revoked,
		Number:                    big.NewInt(mathrand.Int63()),
		ThisUpdate:                time.Now().Add(-1 * time.Minute),
		NextUpdate:                time.Now().Add(60 * time.Minute),
	}
	signer, ok := caPrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key %s does not implement signer", reflect.TypeOf(caPrivateKey))
	}
	derBytes, err := x509.CreateRevocationList(rand.Reader, template, caX509Cert, signer)
	if err != nil {
		return err
	}
	// Public key
	err = pem.Encode(crlFile, &pem.Block{Type: "X509 CRL", Bytes: derBytes})
	if err != nil {
		return err
	}
	err = crlFile.Sync()
	if err != nil {
		return err
	}
	return nil
}

func GenerateCert(caCert *tls.Certificate, client bool, certFile *os.File, keyFile *os.File) (*tls.Certificate, *x509.Certificate, error) {
	var certificate *x509.Certificate
	if client {
		certificate = &x509.Certificate{
			SerialNumber: big.NewInt(mathrand.Int63()),
			Subject: pkix.Name{
				CommonName: fmt.Sprintf("client-%d", mathrand.Int63()),
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().AddDate(10, 0, 0),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			KeyUsage:    x509.KeyUsageDigitalSignature,
		}

	} else {
		certificate = &x509.Certificate{
			SerialNumber: big.NewInt(mathrand.Int63()),
			Subject: pkix.Name{
				CommonName: fmt.Sprintf("server-%d", mathrand.Int63()),
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().AddDate(10, 0, 0),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:    x509.KeyUsageDigitalSignature,
			DNSNames:    []string{"localhost"},
			IPAddresses: []net.IP{[]byte{127, 0, 0, 1}},
		}
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.CreateCertificate(rand.Reader, certificate, ca, &priv.PublicKey, caCert.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	// Public key
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	if err != nil {
		return nil, nil, err
	}
	err = certFile.Sync()
	if err != nil {
		return nil, nil, err
	}
	// Private key
	err = pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err != nil {
		return nil, nil, err
	}
	err = keyFile.Sync()
	if err != nil {
		return nil, nil, err
	}
	// Load Cert
	caTLS, err := tls.LoadX509KeyPair(certFile.Name(), keyFile.Name())
	if err != nil {
		return nil, nil, err
	}
	x509Cert, err := x509.ParseCertificate(caTLS.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{cert},
		PrivateKey:  priv,
	}, x509Cert, nil
}

func GenerateCA(certFile *os.File, keyFile *os.File) (*tls.Certificate, *x509.Certificate, error) {
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(mathrand.Int63()),
		Subject: pkix.Name{
			CommonName: "ca-cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	caCert, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &caPriv.PublicKey, caPriv)
	if err != nil {
		return nil, nil, err
	}

	// Public key
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCert})
	if err != nil {
		return nil, nil, err
	}
	err = certFile.Sync()
	if err != nil {
		return nil, nil, err
	}
	// Private key
	err = pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPriv)})
	if err != nil {
		return nil, nil, err
	}
	err = keyFile.Sync()
	if err != nil {
		return nil, nil, err
	}
	// Load CA
	caTLS, err := tls.LoadX509KeyPair(certFile.Name(), keyFile.Name())
	if err != nil {
		return nil, nil, err
	}
	x509Cert, err := x509.ParseCertificate(caTLS.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{caCert},
		PrivateKey:  caPriv,
	}, x509Cert, nil
}

type CertsBundle struct {
	dirName string

	CACert     *os.File
	CAKey      *os.File
	CAEmptyCRL *os.File
	CATLSCert  *tls.Certificate
	CAX509Cert *x509.Certificate

	ServerCert         *os.File
	ServerKey          *os.File
	ServerKeyPassword  string
	ServerKeyEncrypted *os.File
	ServerTLSCert      *tls.Certificate
	ServerX509Cert     *x509.Certificate

	ClientCert         *os.File
	ClientKey          *os.File
	ClientKeyPassword  string
	ClientKeyEncrypted *os.File
	ClientCRL          *os.File
	ClientTLSCert      *tls.Certificate
	ClientX509Cert     *x509.Certificate
}

func (bundle *CertsBundle) Close() {
	_ = os.Remove(bundle.CACert.Name())
	_ = os.Remove(bundle.CAKey.Name())
	_ = os.Remove(bundle.ServerCert.Name())
	_ = os.Remove(bundle.ServerKey.Name())
	_ = os.Remove(bundle.ServerKeyEncrypted.Name())
	_ = os.Remove(bundle.ClientCert.Name())
	_ = os.Remove(bundle.ClientKey.Name())
	_ = os.Remove(bundle.ClientKeyEncrypted.Name())
	_ = os.Remove(bundle.dirName)
}

func (bundle *CertsBundle) NewHttpClient() *http.Client {
	return &http.Client{
		Transport: tlsclient.NewDefaultRoundTripper(tlsclient.WithRootCA(bundle.CAX509Cert), tlsclient.WithClientCertificate(bundle.ClientTLSCert)),
	}
}

func NewCertsBundle() *CertsBundle {
	dirName, err := os.MkdirTemp("", "tls-test-")
	if err != nil {
		panic(err)
	}
	bundle := &CertsBundle{}
	bundle.CACert, err = os.CreateTemp(dirName, "ca-cert-")
	if err != nil {
		panic(err)
	}
	defer closeFile(bundle.CACert)

	bundle.CAKey, err = os.CreateTemp(dirName, "ca-key-")
	if err != nil {
		panic(err)
	}
	defer closeFile(bundle.CAKey)

	bundle.CAEmptyCRL, err = os.CreateTemp(dirName, "ca-empty-crl")
	if err != nil {
		panic(err)
	}
	defer closeFile(bundle.CAEmptyCRL)

	bundle.ServerCert, err = os.CreateTemp(dirName, "server-cert-")
	if err != nil {
		panic(err)
	}
	defer closeFile(bundle.ServerCert)

	bundle.ServerKey, err = os.CreateTemp(dirName, "server-key-")
	if err != nil {
		panic(err)
	}
	defer closeFile(bundle.ServerKey)

	bundle.ServerKeyEncrypted, err = os.CreateTemp(dirName, "server-key-encrypted-")
	if err != nil {
		panic(err)
	}
	defer closeFile(bundle.ServerKeyEncrypted)

	bundle.ClientCert, err = os.CreateTemp(dirName, "client-cert-")
	if err != nil {
		panic(err)
	}
	defer closeFile(bundle.ClientCert)

	bundle.ClientKey, err = os.CreateTemp("", "client-key-")
	if err != nil {
		panic(err)
	}
	defer closeFile(bundle.ClientKey)

	bundle.ClientKeyEncrypted, err = os.CreateTemp("", "client-key-encrypted-")
	if err != nil {
		panic(err)
	}
	defer closeFile(bundle.ClientKeyEncrypted)

	bundle.ClientCRL, err = os.CreateTemp("", "client-crl-")
	if err != nil {
		panic(err)
	}
	defer closeFile(bundle.ClientCRL)

	// generate certs
	bundle.CATLSCert, bundle.CAX509Cert, err = GenerateCA(bundle.CACert, bundle.CAKey)
	if err != nil {
		panic(err)
	}
	bundle.ServerTLSCert, bundle.ServerX509Cert, err = GenerateCert(bundle.CATLSCert, false, bundle.ServerCert, bundle.ServerKey)
	if err != nil {
		panic(err)
	}
	if bundle.ServerKeyPassword == "" {
		bundle.ServerKeyPassword = DefaultKeyPassword
	}
	writeEncryptedPrivate(bundle.ServerKey.Name(), bundle.ServerKeyEncrypted, bundle.ServerKeyPassword)

	bundle.ClientTLSCert, bundle.ClientX509Cert, err = GenerateCert(bundle.CATLSCert, true, bundle.ClientCert, bundle.ClientKey)
	if err != nil {
		panic(err)
	}
	if bundle.ClientKeyPassword == "" {
		bundle.ClientKeyPassword = DefaultKeyPassword
	}
	writeEncryptedPrivate(bundle.ClientKey.Name(), bundle.ClientKeyEncrypted, bundle.ClientKeyPassword)

	// generate CRLs
	err = GenerateCRL(bundle.CAX509Cert, bundle.CATLSCert.PrivateKey, []*x509.Certificate{}, bundle.CAEmptyCRL)
	if err != nil {
		panic(err)
	}
	err = GenerateCRL(bundle.CAX509Cert, bundle.CATLSCert.PrivateKey, []*x509.Certificate{bundle.ClientX509Cert}, bundle.ClientCRL)
	if err != nil {
		panic(err)
	}
	return bundle
}

func writeEncryptedPrivate(keyFilename string, encryptedFile *os.File, password string) {
	keyData, err := os.ReadFile(keyFilename)
	if err != nil {
		panic(err)
	}
	encryptedKey, err := keyutil.EncryptPKCS8PrivateKeyPEM(keyData, password)
	if err != nil {
		panic(err)
	}

	_, err = io.Copy(encryptedFile, bytes.NewReader(encryptedKey))
	if err != nil {
		panic(err)
	}
}

func closeFile(file *os.File) {
	err := file.Close()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
	}
}
