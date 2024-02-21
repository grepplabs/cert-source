package tlsserver

import "crypto/tls"

type TLSServerConfigOption func(*tls.Config)

func WithTLSServerNextProtos(nextProto []string) TLSServerConfigOption {
	return func(c *tls.Config) {
		c.NextProtos = nextProto
	}
}
