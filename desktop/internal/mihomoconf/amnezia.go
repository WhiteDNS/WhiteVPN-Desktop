package mihomoconf

// The obfuscation parameters an AmneziaWG link carries.
//
// AmneziaWG is WireGuard with the handshake disguised: junk packets before it,
// padded header sizes, and magic header values other than WireGuard's own. A
// server configured that way only answers a client sending the same numbers, so
// the numbers are part of the credential, not a preference.
//
// They were being thrown away. parseWireGuard read the keys, the addresses and
// the MTU and ignored every Amnezia parameter, so an AmneziaWG link imported as
// plain WireGuard — and then the global noise setting was written over the top,
// which is one server's numbers applied to a different server. The link would
// sit in the list looking importable and never connect.
//
// Only the fields the pinned core understands are emitted. mihomo decodes this
// map into a struct and rejects keys it has no field for, so a parameter added
// upstream later has to arrive with the core that knows it — otherwise every
// WireGuard proxy in the subscription fails to load, not just this one.

import (
	"strconv"
	"strings"
)

// amneziaIntFields are the parameters mihomo reads as numbers, with the
// spellings links use for each.
//
//	jc         how many junk packets before the handshake
//	jmin/jmax  their size range
//	s1..s4     padding prepended to the handshake messages
//	itime      v1.5's rekey interval
var amneziaIntFields = map[string][]string{
	"jc":    {"jc", "junk_packet_count", "junkpacketcount"},
	"jmin":  {"jmin", "junk_packet_min_size", "junkpacketminsize"},
	"jmax":  {"jmax", "junk_packet_max_size", "junkpacketmaxsize"},
	"s1":    {"s1", "init_packet_junk_size", "initpacketjunksize"},
	"s2":    {"s2", "response_packet_junk_size", "responsepacketjunksize"},
	"s3":    {"s3", "cookie_reply_packet_junk_size"},
	"s4":    {"s4", "transport_packet_junk_size"},
	"itime": {"itime", "special_handshake_timeout"},
}

// amneziaStringFields are the ones mihomo reads as strings. The magic headers
// are numbers on the wire but arrive as text, and i1..i5 and j1..j3 are packet
// templates rather than values.
var amneziaStringFields = map[string][]string{
	"h1": {"h1", "init_packet_magic_header", "initpacketmagicheader"},
	"h2": {"h2", "response_packet_magic_header", "responsepacketmagicheader"},
	"h3": {"h3", "underload_packet_magic_header", "underloadpacketmagicheader"},
	"h4": {"h4", "transport_packet_magic_header", "transportpacketmagicheader"},
	"i1": {"i1"},
	"i2": {"i2"},
	"i3": {"i3"},
	"i4": {"i4"},
	"i5": {"i5"},
	"j1": {"j1"},
	"j2": {"j2"},
	"j3": {"j3"},
}

// amneziaV3Fields are the ones that exist only in AmneziaWG v3. The core writes
// every one of these into the device's IPC config, and the legacy device rejects
// keys it does not know — so they are only ever emitted alongside version 3.
var amneziaV3Fields = map[string][]string{
	"header-protection-key":    {"header-protection-key", "header_protection_key", "hpk"},
	"content-padding-addition": {"content-padding-addition", "content_padding_addition"},
	"rekey-after-time":         {"rekey-after-time", "rekey_after_time"},
	"rekey-timeout":            {"rekey-timeout", "rekey_timeout"},
	"reject-after-time":        {"reject-after-time", "reject_after_time"},
	"keepalive-timeout":        {"keepalive-timeout", "keepalive_timeout"},
	"max-handshake-attempts":   {"max-handshake-attempts", "max_handshake_attempts"},
}

// amneziaV3BoolFields arrived in v3.1.
var amneziaV3BoolFields = map[string][]string{
	"random-trailers": {"random-trailers", "random_trailers"},
	"disable-cookies": {"disable-cookies", "disable_cookies"},
}

// amneziaV15OnlyFields were removed in v2 and cannot travel with the v3 set.
var amneziaV15OnlyFields = []string{"j1", "j2", "j3", "itime"}

// amneziaFromQuery reads whatever Amnezia parameters a link carries.
//
// Returns nil when it carries none, so a plain WireGuard link stays plain: an
// empty amnezia-wg-option is not the same as no amnezia-wg-option, and writing
// one would turn every WireGuard proxy into an AmneziaWG proxy with all the
// defaults, which no server is expecting.
func amneziaFromQuery(query map[string]string) map[string]any {
	options := map[string]any{}

	for field, spellings := range amneziaIntFields {
		raw := firstQueryValue(query, spellings...)
		if raw == "" {
			continue
		}
		// Not parseIntOrZero: zero is a legal value for every one of these —
		// jc=0 means no junk packets, which is a different instruction from
		// "unset" — so a value that will not parse has to be dropped rather
		// than become a zero the user did not ask for.
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 {
			continue
		}
		options[field] = value
	}

	for field, spellings := range amneziaStringFields {
		if value := firstQueryValue(query, spellings...); value != "" {
			options[field] = value
		}
	}

	for field, spellings := range amneziaV3Fields {
		if value := firstQueryValue(query, spellings...); value != "" {
			options[field] = value
		}
	}
	for field, spellings := range amneziaV3BoolFields {
		if value := firstQueryValue(query, spellings...); value != "" {
			options[field] = strings.EqualFold(value, "true") || value == "1"
		}
	}

	if len(options) == 0 {
		return nil
	}
	reconcileAmneziaVersion(options, firstQueryValue(query, "version", "amnezia_version"))
	return options
}

// reconcileAmneziaVersion settles which protocol the options describe, and drops
// what does not belong to it.
//
// The two sets are mutually exclusive at the device: version 3 builds a
// different WireGuard device from the legacy one, and each rejects the other's
// keys outright. Since a rejected key fails the whole configuration rather than
// this one proxy, a link carrying both has to be resolved here rather than sent
// on to find out.
//
// The version decides, because it is the server saying which protocol it speaks.
// Where it is absent and v3-only fields are present, the fields decide instead:
// those parameters exist nowhere else, so their presence is the same statement.
// That is a reading rather than a guess — under any other one the link means
// nothing at all.
func reconcileAmneziaVersion(options map[string]any, declared string) {
	version, err := strconv.Atoi(strings.TrimSpace(declared))
	if err != nil {
		version = 0
	}

	v3Present := false
	for _, set := range []map[string][]string{amneziaV3Fields, amneziaV3BoolFields} {
		for field := range set {
			if _, ok := options[field]; ok {
				v3Present = true
			}
		}
	}
	if version == 0 && v3Present {
		version = 3
	}

	if version == 3 {
		options["version"] = 3
		for _, field := range amneziaV15OnlyFields {
			delete(options, field)
		}
		return
	}
	// Not v3: the v3-only parameters cannot reach the legacy device.
	for _, set := range []map[string][]string{amneziaV3Fields, amneziaV3BoolFields} {
		for field := range set {
			delete(options, field)
		}
	}
	if version != 0 {
		options["version"] = version
	}
}
