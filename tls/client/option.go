package tlsclient

import "crypto/tls"

type TLSClientConfigOption func(*tls.Config)

var (
	http2OnlyNextProtos      = []string{"h2"}
	http2AndHTTP11NextProtos = []string{"h2", "http/1.1"}
)

func WithTLSClientNextProtos(nextProto []string) TLSClientConfigOption {
	return func(c *tls.Config) {
		c.NextProtos = nextProto
	}
}

func WithTLSClientHTTP2() TLSClientConfigOption {
	return WithTLSClientNextProtos(http2OnlyNextProtos)
}

func WithTLSClientHTTP2AndHTTP11() TLSClientConfigOption {
	return WithTLSClientNextProtos(http2AndHTTP11NextProtos)
}

func WithTLSServerName(serverName string) TLSClientConfigOption {
	return func(c *tls.Config) {
		c.ServerName = serverName
	}
}
