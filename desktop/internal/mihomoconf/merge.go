package mihomoconf

// Merging several subscriptions into one list of servers.
//
// The app connects through one subscription at a time, which is the shape the
// phone has and the shape most people want. But somebody with four providers
// added is not thinking about four lists — they are thinking about one pool of
// servers and wanting the best of it, and having to guess which list today's
// working node is in is the app making its own bookkeeping their problem.
//
// So the sources are read as they always were, one at a time, and merged here
// into a single list that everything downstream treats like any other
// subscription body.

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// MergedSource is one subscription's contribution to a merged list.
type MergedSource struct {
	// Name is the subscription's own name, used to tell nodes apart when two
	// providers have named theirs the same thing.
	Name string
	// Proxies is what that subscription yielded.
	Proxies []Proxy
}

// MergeProxies joins several sources into one list, in the order given.
//
// Two things have to be handled and neither is optional.
//
// **Names collide.** Providers name nodes for where they are, so "Germany 01"
// exists in most lists and every name here has to be unique: the engine keys
// its proxies by name, a group naming one twice is a group with a node missing,
// and a node the user pins by name has to resolve to the one they clicked. A
// repeat is qualified with the subscription it came from, which is also the
// answer to "where did this node come from" that a merged list otherwise loses.
//
// **The same server appears twice.** Providers resell each other, and a node
// reached at the same address and port with the same credentials is the same
// node however many lists carry it. Keeping both would measure it twice, show
// it twice, and make "connect to the fastest" pick between two entries for one
// machine. The first source wins, because the earlier list is the one the user
// put first.
func MergeProxies(sources []MergedSource) []Proxy {
	merged := make([]Proxy, 0)
	names := newNameRegistry()
	seen := make(map[string]bool)

	for _, source := range sources {
		for _, proxy := range source.Proxies {
			if key := identityOf(proxy); key != "" {
				if seen[key] {
					continue
				}
				seen[key] = true
			}
			copied := make(Proxy, len(proxy))
			for field, value := range proxy {
				copied[field] = value
			}
			copied["name"] = names.register(qualify(proxy.Name(), source.Name, names))
			merged = append(merged, copied)
		}
	}
	return merged
}

// qualify keeps a name as it is until it has already been taken, and only then
// says which subscription this one came from.
//
// Unqualified while it can be: a list where every node reads "My provider ·
// Germany 01" is harder to scan than one where the prefix appears only on the
// rows that needed telling apart.
func qualify(name, source string, names *nameRegistry) string {
	name = strings.TrimSpace(name)
	source = strings.TrimSpace(source)
	if name == "" {
		name = source
	}
	if source == "" || !names.taken(name) {
		return name
	}
	return source + " · " + name
}

// identityOf is what makes two entries the same node.
//
// Address, port and credential — not the name, which providers choose freely,
// and not the whole definition, which differs in fields that do not change
// where the traffic goes. Empty when there is not enough to be sure, and an
// entry that cannot be identified is kept rather than guessed at: showing one
// node twice is a smaller fault than dropping one that was not a duplicate.
func identityOf(proxy Proxy) string {
	server := strings.TrimSpace(stringField(proxy, "server"))
	if server == "" {
		return ""
	}
	credential := stringField(proxy, "uuid")
	if credential == "" {
		credential = stringField(proxy, "password")
	}
	return strings.ToLower(fmt.Sprintf("%s|%s|%v|%s",
		proxyType(proxy), server, proxy["port"], credential))
}

// MergedDocument renders merged proxies as a mihomo document.
//
// A document rather than share links, because not every proxy came from one —
// a subscription served as YAML has no link to give back — and because this is
// read straight back by ParseDocument, which is the same path a provider's own
// document takes.
func MergedDocument(proxies []Proxy) (string, error) {
	if len(proxies) == 0 {
		return "", fmt.Errorf("mihomoconf: no proxies to merge")
	}
	encoded, err := yaml.Marshal(map[string]any{"proxies": proxies})
	if err != nil {
		return "", fmt.Errorf("mihomoconf: render merged proxies: %w", err)
	}
	return string(encoded), nil
}
