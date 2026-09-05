package tlsserver

import (
	"crypto/tls"
)

type TLSServerConfigOption func(*tls.Config)

var (
	http2OnlyNextProtos      = []string{"h2"}
	http2AndHTTP11NextProtos = []string{"h2", "http/1.1"}
)

func WithTLSServerNextProtos(nextProto []string) TLSServerConfigOption {
	return func(c *tls.Config) {
		c.NextProtos = nextProto
	}
}

func WithTLSServerHTTP2() TLSServerConfigOption {
	return WithTLSServerNextProtos(http2OnlyNextProtos)
}

func WithTLSServerHTTP2AndHTTP11() TLSServerConfigOption {
	return WithTLSServerNextProtos(http2AndHTTP11NextProtos)
}

func WithTLSServerMinVersion(minVersion uint16) TLSServerConfigOption {
	return func(c *tls.Config) {
		c.MinVersion = minVersion
	}
}

func WithTLSServerCurvePreferences(curvePreferences []tls.CurveID) TLSServerConfigOption {
	return func(c *tls.Config) {
		if len(curvePreferences) != 0 {
			c.CurvePreferences = curvePreferences
		} else {
			c.CurvePreferences = nil
		}
	}
}

func WithTLSServerCipherSuites(cipherSuites []uint16) TLSServerConfigOption {
	return func(c *tls.Config) {
		if len(cipherSuites) != 0 {
			c.CipherSuites = cipherSuites
		} else {
			c.CipherSuites = nil
		}
	}
}

type VerifyConnectionFunc func(cs tls.ConnectionState) error

// WithTLSServerVerifyConnection sets or chains a custom VerifyConnection function on a *tls.Config.
// If a nil function is provided, it unsets the certificate verification function.
// If an existing verification function is present, the new function is chained so that it is invoked only if the existing one succeeds.
func WithTLSServerVerifyConnection(verifyFunc VerifyConnectionFunc) TLSServerConfigOption {
	return func(c *tls.Config) {
		if verifyFunc == nil {
			c.VerifyConnection = nil
			return
		}
		prevFunc := c.VerifyConnection
		if prevFunc == nil {
			c.VerifyConnection = verifyFunc
			return
		}
		c.VerifyConnection = func(cs tls.ConnectionState) error {
			if err := prevFunc(cs); err != nil {
				return err
			}
			return verifyFunc(cs)
		}
	}
}
