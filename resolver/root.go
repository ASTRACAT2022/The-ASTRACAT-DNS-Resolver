package resolver

import (
	"strings"
	"time"

	"github.com/miekg/dns"
)

// namedRootData is a multi-line string containing the root DNS server hints.
// This is the same data from your previous immersive artifact.
const namedRootData = `
;       This file holds the information on root name servers needed to 
;       initialize cache of Internet domain name servers
;       (e.g. reference this file in the "cache  .  <file>"
;       configuration file of BIND domain name servers). 
; 
;       This file is made available by InterNIC 
;       under anonymous FTP as
;           file                /domain/named.cache 
;           on server           FTP.INTERNIC.NET
;       -OR-                    RS.INTERNIC.NET
;
;       last update:     July 24, 2025
;       related version of root zone:     2025072401
; 
; FORMERLY NS.INTERNIC.NET 
;
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
; 
; FORMERLY NS1.ISI.EDU 
;
.                        3600000      NS    B.ROOT-SERVERS.NET.
B.ROOT-SERVERS.NET.      3600000      A     170.247.170.2
B.ROOT-SERVERS.NET.      3600000      AAAA  2801:1b8:10::b
; 
; FORMERLY C.PSI.NET 
;
.                        3600000      NS    C.ROOT-SERVERS.NET.
C.ROOT-SERVERS.NET.      3600000      A     192.33.4.12
C.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2::c
; 
; FORMERLY NS.ISC.ORG
;
.                        3600000      NS    D.ROOT-SERVERS.NET.
D.ROOT-SERVERS.NET.      3600000      A     199.7.91.13
D.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2d::d
;
; FORMERLY NS.NASA.GOV
;
.                        3600000      NS    E.ROOT-SERVERS.NET.
E.ROOT-SERVERS.NET.      3600000      A     192.203.230.10
E.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:a8::e
;
; FORMERLY NS.NYSER.NET
;
.                        3600000      NS    F.ROOT-SERVERS.NET.
F.ROOT-SERVERS.NET.      3600000      A     192.5.5.241
F.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2f::f
; 
; FORMERLY NS.NIC.DDN.MIL
;
.                        3600000      NS    G.ROOT-SERVERS.NET.
G.ROOT-SERVERS.NET.      3600000      A     192.112.36.4
G.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:12::d0d
; 
; FORMERLY AOS.ARL.ARMY.MIL
;
.                        3600000      NS    H.ROOT-SERVERS.NET.
H.ROOT-SERVERS.NET.      3600000      A     198.97.190.53
H.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:1::53
; 
; FORMERLY NIC.NORDU.NET
;
.                        3600000      NS    I.ROOT-SERVERS.NET.
I.ROOT-SERVERS.NET.      3600000      A     192.36.148.17
I.ROOT-SERVERS.NET.      3600000      AAAA  2001:7fe::53
; 
; OPERATED BY VERISIGN, INC.
;
.                        3600000      NS    J.ROOT-SERVERS.NET.
J.ROOT-SERVERS.NET.      3600000      A     192.58.128.30
J.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:c27::2:30
;
;
.                        3600000      NS    K.ROOT-SERVERS.NET.
K.ROOT-SERVERS.NET.      3600000      A     193.0.14.129
K.ROOT-SERVERS.NET.      3600000      AAAA  2001:7fd::1
;
;
.                        3600000      NS    L.ROOT-SERVERS.NET.
L.ROOT-SERVERS.NET.      3600000      A     199.7.83.42
L.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:9f::42
;
;
.                        3600000      NS    M.ROOT-SERVERS.NET.
M.ROOT-SERVERS.NET.      3600000      A     202.12.27.33
M.ROOT-SERVERS.NET.      3600000      AAAA  2001:dc3::35
`

// loadRootServers parses the namedRootData string into a map of DNS records.
// This is done once at startup to improve performance.
func loadRootServers() map[string][]dns.RR {
	rootServers := make(map[string][]dns.RR)
	
	// Use the miekg/dns library to parse the zone file.
	zp := dns.NewZoneParser(strings.NewReader(namedRootData), ".", "")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch rr.Header().Rrtype {
		case dns.TypeA, dns.TypeAAAA:
			// Extract NS records and their corresponding A/AAAA records
			// This part is for illustrative purposes; the actual resolution
			// will still start with the hardcoded list for speed.
			// The main goal here is to parse all records into a usable format.
			rrName := strings.TrimSuffix(rr.Header().Name, ".")
			rootServers[rrName] = append(rootServers[rrName], rr)
		}
	}

	return rootServers
}

// InitialRootServers is a static, hardcoded list of root server addresses.
// It is used as the starting point for all DNS queries.
var InitialRootServers = []string{
    "198.41.0.4:53",
    "2001:503:ba3e::2:30:53",
    "170.247.170.2:53",
    "192.33.4.12:53",
    "2001:500:2::c:53",
    "199.7.91.13:53",
    "2001:500:2d::d:53",
    "192.203.230.10:53",
    "2001:500:a8::e:53",
    "192.5.5.241:53",
    "2001:500:2f::f:53",
    "192.112.36.4:53",
    "2001:500:12::d0d:53",
    "198.97.190.53:53",
    "2001:500:1::53:53",
    "192.36.148.17:53",
    "2001:7fe::53:53",
    "192.58.128.30:53",
    "2001:503:c27::2:30:53",
    "193.0.14.129:53",
    "2001:7fd::1:53",
    "199.7.83.42:53",
    "2001:500:9f::42:53",
    "202.12.27.33:53",
    "2001:dc3::35:53",
}
