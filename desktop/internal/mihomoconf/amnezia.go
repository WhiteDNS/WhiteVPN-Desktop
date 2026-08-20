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

import "strconv"

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

	if len(options) == 0 {
		return nil
	}
	return options
}
