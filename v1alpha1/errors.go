package v1alpha1

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strings"

	v1 "github.com/cnuss/libtunnel/v1"
)

// Classify names err with the v1 failure class that describes it.
//
// An error that already carries a class is returned as it arrived. A provider
// naming a verdict only its own protocol can read — a mint refused, a 429 —
// has already done the classification, and re-reading it here would only lose
// information. Everything else is read at the transport level, which every
// backend shares, so a backend never needs a classifier of its own: it tags
// what only it can see and lets this decide the rest.
//
// Whether the result is worth retrying is deliberately not a second return
// value. It is v1.Budget(class) > 0, which cannot drift out of step with the
// class the way a parallel table could.
func Classify(err error) error {
	if err == nil {
		return nil
	}

	for _, known := range []error{
		v1.ErrCertificate,
		v1.ErrRejected,
		v1.ErrProviderUnreachable,
		v1.ErrEdgeUnreachable,
		v1.ErrRateLimited,
		v1.ErrClosed,
	} {
		if errors.Is(err, known) {
			return known
		}
	}

	// A certificate the client cannot verify means a missing trust store, a
	// wrong clock, or an intercepting proxy — permanent conditions a retry
	// cannot see, let alone fix. This is where hashicorp/go-retryablehttp
	// draws the same line.
	var verification *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var badHostname x509.HostnameError
	var invalidCert x509.CertificateInvalidError
	if errors.As(err, &verification) ||
		errors.As(err, &unknownAuthority) ||
		errors.As(err, &badHostname) ||
		errors.As(err, &invalidCert) {
		return v1.ErrCertificate
	}

	// NXDOMAIN is the resolver saying the host does not exist, and it will
	// keep saying so — a typo'd provider, not a slow one. A resolver that is
	// merely not up yet reports something else (SERVFAIL, a timeout) and
	// falls through to the retryable class at the bottom.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return v1.ErrRejected
	}

	// A request the client could not even build. net/http reports both of
	// these as plain text inside a *url.Error with no type to match on, so
	// matching the text is the only handle there is — the same compromise
	// go-retryablehttp makes with its regexps.
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		msg := urlErr.Err.Error()
		if strings.Contains(msg, "unsupported protocol scheme") ||
			strings.Contains(msg, "invalid header field") {
			return v1.ErrRejected
		}
	}

	// Everything unrecognized is retryable but bounded. An unanticipated
	// failure must still terminate: a class with a budget is what keeps a
	// caller that passed context.Background() from hanging forever.
	return v1.ErrProviderUnreachable
}
