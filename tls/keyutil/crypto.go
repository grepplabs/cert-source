package keyutil

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/youmark/pkcs8"
)

func DecryptPrivateKeyPEM(pemData []byte, password string) ([]byte, error) {
	keyBlock, _ := pem.Decode(pemData)
	if keyBlock == nil {
		return nil, errors.New("failed to parse PEM")
	}
	if x509.IsEncryptedPEMBlock(keyBlock) {
		if password == "" {
			return nil, errors.New("PEM is encrypted, but password is empty")
		}
		key, err := x509.DecryptPEMBlock(keyBlock, []byte(password))
		if err != nil {
			return nil, err
		}
		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: key,
		}
		return pem.EncodeToMemory(block), nil
	} else if strings.Contains(string(pemData), "ENCRYPTED PRIVATE KEY") {
		if password == "" {
			return nil, errors.New("PEM is encrypted, but password is empty")
		}
		key, err := pkcs8.ParsePKCS8PrivateKey(keyBlock.Bytes, []byte(password))
		if err != nil {
			return nil, err
		}
		return MarshalPrivateKeyToPEM(key)
	}
	return pemData, nil
}
