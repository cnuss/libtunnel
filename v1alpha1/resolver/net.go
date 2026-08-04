package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// netResolver resolves by walking the delegation itself: it asks a TLD server
// which nameservers hold the zone, then asks one of those directly. Neither
// step passes through a recursive resolver, so neither can return a cached
// negative — which is the whole reason it exists. A hostname published seconds
// ago resolves as soon as its own nameservers serve it.
//
// A TLD server cannot answer for the hostname itself; it is authoritative for
// the parent zone and replies with a referral, carrying the zone's nameservers
// and their addresses. Asking it directly for the hostname yields nothing,
// because following a referral is what a recursive resolver does and this is
// deliberately not one.
//
// It is used only where the network carries such queries honestly; see
// isHijacked.
type netResolver struct {
	// servers are TLD nameservers, queried in random order, without a port.
	servers []string
	// fallback resolves the hostname when the walk produces nothing.
	fallback Resolver
}

var _ Resolver = &netResolver{}

// queryTimeout bounds a single exchange. Nameservers answer in tens of
// milliseconds; this is a ceiling on an unresponsive one, not a normal cost.
const queryTimeout = 3 * time.Second

// nameserverPort is where glue addresses are dialed. Glue carries an address
// and no port, so it is always 53 in practice; it is a variable only so tests
// can point the walk at a stub.
var nameserverPort = "53"

// Resolve implements [Resolver]. For each TLD server in turn it reads the
// zone's delegation and asks the zone's own nameservers, returning the first
// non-empty answer. It falls back only when the walk yields nothing.
func (r *netResolver) Resolve(hostname string) Records {
	records := Records{
		CNAME: hostname,
	}

	for _, server := range shuffled(r.servers) {
		for _, nameserver := range delegation(server, hostname) {
			records.A = lookupAt(nameserver, hostname, dnsmessage.TypeA)
			records.AAAA = lookupAt(nameserver, hostname, dnsmessage.TypeAAAA)
			if !records.Empty() {
				return records
			}
		}
	}

	return r.fallback.Resolve(hostname)
}

// delegation asks server which nameservers hold hostname's zone and returns
// their addresses, taken from the glue the referral carries.
//
// The glue is used rather than the nameserver names: resolving those names
// would mean asking a recursive resolver, which is the thing this path exists
// to avoid.
func delegation(server, hostname string) []string {
	query, err := buildQuery(hostname, dnsmessage.TypeA, false)
	if err != nil {
		return nil
	}
	wire, err := exchangeUDP(server, query)
	if err != nil {
		return nil
	}
	addrs, err := parseGlue(wire)
	if err != nil {
		return nil
	}

	servers := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		servers = append(servers, net.JoinHostPort(addr.String(), nameserverPort))
	}
	// Randomized so one nameserver does not carry every lookup.
	return shuffled(servers)
}

// lookupAt asks one nameserver directly for hostname's records of type qtype.
// A nameserver that does not answer, or does not yet hold the record, yields
// nothing and the caller moves on.
func lookupAt(nameserver, hostname string, qtype dnsmessage.Type) []netip.Addr {
	query, err := buildQuery(hostname, qtype, false)
	if err != nil {
		return nil
	}
	wire, err := exchangeUDP(nameserver, query)
	if err != nil {
		return nil
	}
	addrs, err := parseAnswer(wire, qtype)
	if err != nil {
		return nil
	}
	return addrs
}

// exchangeUDP sends one query to server and returns the reply. server may omit
// the port, in which case 53 is assumed.
func exchangeUDP(server string, query []byte) ([]byte, error) {
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}

	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, maxUDPResponse)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// parseGlue extracts the nameserver addresses from a referral's additional
// section. A reply that runs out mid-section is read for whatever it did carry:
// one usable address is enough to continue the walk.
func parseGlue(wire []byte) ([]netip.Addr, error) {
	var p dnsmessage.Parser
	if _, err := p.Start(wire); err != nil {
		return nil, fmt.Errorf("malformed DNS response: %w", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}
	if err := p.SkipAllAnswers(); err != nil {
		return nil, err
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return nil, err
	}

	var addrs []netip.Addr
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			return addrs, nil // section done, or truncated: keep what was read
		}
		switch h.Type {
		case dnsmessage.TypeA:
			rr, err := p.AResource()
			if err != nil {
				return addrs, nil
			}
			addrs = append(addrs, netip.AddrFrom4(rr.A))
		case dnsmessage.TypeAAAA:
			rr, err := p.AAAAResource()
			if err != nil {
				return addrs, nil
			}
			addrs = append(addrs, netip.AddrFrom16(rr.AAAA))
		default:
			if err := p.SkipAdditional(); err != nil {
				return addrs, nil
			}
		}
	}
}
