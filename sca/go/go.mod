// File:    go.mod
// Purpose: SCA fixture. Go module manifest pinned to known-vulnerable releases.
//          DO NOT BUILD.
// Author:  Vigilnz Security Engineering
// Date:    2026-10-16

module github.com/vigilnz/fixtures/vuln-corpus-go

go 1.21

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // CVE-2020-26160 - audience bypass
	github.com/gin-gonic/gin v1.6.3 // CVE-2020-28483 - header spoofing
	github.com/gogo/protobuf v1.3.1 // CVE-2021-3121 - unmarshal panic
	golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2 // CVE-2020-29652 - SSH NULL deref
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110 // CVE-2021-33194 - html parser DoS
	golang.org/x/text v0.3.0 // CVE-2020-14040 - UTF-16 decode loop
	gopkg.in/yaml.v2 v2.2.2 // CVE-2019-11253 - billion laughs
	github.com/prometheus/client_golang v1.11.0 // CVE-2022-21698 - metric cardinality DoS
	github.com/opencontainers/runc v1.0.0-rc9 // CVE-2021-30465 - symlink mount escape
)
