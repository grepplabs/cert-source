package keyutil

import (
	"bytes"
	"crypto"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateKeys(t *testing.T) {
	tests := []struct {
		name        string
		genKeysFunc func() (crypto.PrivateKey, []byte, crypto.PublicKey, []byte, error)
	}{
		{
			name:        "generate RSA key",
			genKeysFunc: GenerateRSAKeys,
		},
		{
			name:        "generate EC keys",
			genKeysFunc: GenerateECKeys,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			privKey, privPem, pubKey, pubPem, err := tc.genKeysFunc()
			require.NoError(t, err)
			require.True(t, KeysMatch(privKey, pubKey))

			privateKey, err := ReadPrivateKey(bytes.NewReader(privPem))
			require.NoError(t, err)
			require.Equal(t, privateKey, privKey)
			publicKeys, err := ReadPublicKeys(bytes.NewReader(pubPem))
			require.NoError(t, err)
			require.Len(t, publicKeys, 1)
			require.True(t, KeysMatch(privateKey, publicKeys[0]))

			publicKeys, err = ReadPublicKeys(bytes.NewReader(privPem))
			require.Len(t, publicKeys, 1)
			require.NoError(t, err)

			privateKey, err = ParsePrivateKeyPEM(privPem)
			require.NoError(t, err)
			publicKeys, err = ParsePublicKeysPEM(pubPem)
			require.NoError(t, err)

			privPem, err = MarshalPrivateKeyToPEM(privateKey)
			require.NoError(t, err)
			require.NotNil(t, privPem)

			pubPem, err = MarshalPublicKeyToPEM(publicKeys[0])
			require.NoError(t, err)
			require.NotNil(t, pubPem)
		})
	}
}

func TestReadKeys(t *testing.T) {
	tests := []struct {
		name        string
		genKeysFunc func() (crypto.PrivateKey, []byte, crypto.PublicKey, []byte, error)
	}{
		{
			name:        "generate and read RSA key",
			genKeysFunc: GenerateRSAKeys,
		},
		{
			name:        "generate and read EC keys",
			genKeysFunc: GenerateECKeys,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			dirName, err := os.MkdirTemp("", "key-test-")
			require.NoError(t, err)
			privFile, err := os.CreateTemp(dirName, "private-key-")
			require.NoError(t, err)
			defer func() {
				_ = os.Remove(privFile.Name())
			}()

			pubFile, err := os.CreateTemp(dirName, "public-key-")
			require.NoError(t, err)
			defer func() {
				_ = os.Remove(pubFile.Name())
			}()

			_, privPem, _, pubPem, err := tc.genKeysFunc()
			require.NoError(t, err)

			_, err = io.Copy(privFile, bytes.NewReader(privPem))
			require.NoError(t, err)
			_ = privFile.Close()

			_, err = io.Copy(pubFile, bytes.NewReader(pubPem))
			require.NoError(t, err)
			_ = pubFile.Close()

			privKey, err := ReadPrivateKeyFile(privFile.Name())
			require.NoError(t, err)

			pubKey, err := ReadPublicKeyFile(pubFile.Name())
			require.NoError(t, err)
			require.True(t, KeysMatch(privKey, pubKey))

		})
	}
}
