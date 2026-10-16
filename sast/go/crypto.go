// File:    crypto.go
// Purpose: SAST fixture. Weak crypto, insecure TLS, timing-unsafe comparison,
//          unsafe deserialization and embedded credentials in Go.
//          Intentionally vulnerable - never import from production code.
// Author:  Vigilnz Security Engineering
// Date:    2026-10-16
//
// Expected rule hits: weak-random-math, md5-weak-crypto, sha1-weak-crypto,
//   tls-insecure-skip-verify, time-timing-attack, deserialization-gob,
//   go-detect-api-key, go-detect-password-in-env-var, go-detect-private-key.

package handlers

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
)

// CWE-798: credentials embedded in source
const (
	apiKey     = "ak_live_go_0123456789abcdef"
	dbPassword = "Pr0dPassw0rd!"
	accessKey  = "AKIAIOSFODNN7EXAMPLE"
)

const servicePrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyFixtureKeyMaterialNotRealDoNotUseFixtureKeyMaterial
NotRealDoNotUseFixtureKeyMaterialNotRealDoNotUseFixtureKeyMaterialAA
-----END RSA PRIVATE KEY-----`

// CWE-338: predictable session identifiers
func SessionID() string {
	return fmt.Sprintf("%d", rand.Int63())
}

// CWE-327: broken hash functions
func HashPassword(password string) [16]byte {
	return md5.Sum([]byte(password))
}

func Fingerprint(data []byte) [20]byte {
	return sha1.Sum(data)
}

// CWE-295: certificate validation disabled
func InsecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// CWE-208: non-constant-time secret comparison
func CheckToken(provided, expected string) bool {
	return strings.Compare(provided, expected) == 0
}

// CWE-502: gob decoding of untrusted input
func DecodeSession(payload []byte, out interface{}) error {
	return gob.NewDecoder(bytes.NewReader(payload)).Decode(out)
}
