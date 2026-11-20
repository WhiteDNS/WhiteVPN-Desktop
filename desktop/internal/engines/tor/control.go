package tor

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"regexp"
)

const (
	safeCookieServerKey = "Tor safe cookie authentication server-to-controller hash"
	safeCookieClientKey = "Tor safe cookie authentication controller-to-server hash"
)

var authChallenge = regexp.MustCompile(`^250 AUTHCHALLENGE SERVERHASH=([0-9a-fA-F]{64}) SERVERNONCE=([0-9a-fA-F]{64})$`)

// attachController is Android's TorControlConnection.attach: SAFECOOKIE proves
// the listener is the Tor we started before we prove ourselves to it, and
// TAKEOWNERSHIP makes Tor exit when this connection closes.
func attachController(conn net.Conn, cookie []byte) error {
	if len(cookie) != 32 {
		return errors.New("tor: invalid authentication cookie")
	}
	input := bufio.NewReader(conn)
	command := func(value string) (string, error) {
		if _, err := conn.Write([]byte(value + "\r\n")); err != nil {
			return "", errors.New("tor: controller closed")
		}
		var reply []byte
		for {
			chunk, isPrefix, err := input.ReadLine()
			if err != nil {
				return "", errors.New("tor: controller closed")
			}
			reply = append(reply, chunk...)
			if len(reply) > 4096 {
				return "", errors.New("tor: controller closed")
			}
			if !isPrefix {
				return string(reply), nil
			}
		}
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	challenge, err := command("AUTHCHALLENGE SAFECOOKIE " + hex.EncodeToString(nonce))
	if err != nil {
		return err
	}
	parsed := authChallenge.FindStringSubmatch(challenge)
	if parsed == nil {
		return errors.New("tor: invalid authentication challenge")
	}
	serverHash, _ := hex.DecodeString(parsed[1])
	serverNonce, _ := hex.DecodeString(parsed[2])
	data := append(append(append([]byte{}, cookie...), nonce...), serverNonce...)
	if !hmac.Equal(serverHash, safeCookieHMAC(safeCookieServerKey, data)) {
		return errors.New("tor: controller identity mismatch")
	}
	if reply, err := command("AUTHENTICATE " + hex.EncodeToString(safeCookieHMAC(safeCookieClientKey, data))); err != nil || reply != "250 OK" {
		return errors.New("tor: controller authentication failed")
	}
	if reply, err := command("TAKEOWNERSHIP"); err != nil || reply != "250 OK" {
		return errors.New("tor: ownership was refused")
	}
	return nil
}

func safeCookieHMAC(key string, data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(data)
	return mac.Sum(nil)
}
