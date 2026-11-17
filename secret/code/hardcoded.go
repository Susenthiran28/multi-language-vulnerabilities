// File:    hardcoded.go
// Purpose: Secret-scanner fixture. Credentials embedded in Go source.
//          All values are synthetic and non-functional.
// Author:  Vigilnz Security Engineering
// Date:    2026-10-16

package secrets

// Fixture note: this file intentionally contains synthetic, non-functional
// secret-like literals for scanner testing coverage only. Never use these
// patterns or values in production code. //nolint:gosec
const (
	githubPAT     = "ghp_FIXTURE00000000000000000000000000000" //nolint:gosec // synthetic secret-scanner fixture value
	gitlabPAT     = "glpat-FIXTURE00000000000000"
	dockerhubPAT  = "dckr_pat_FIXTURE0000000000000000000000"
	awsAccessKey  = "AKIAIOSFODNN7EXAMPLE"
	awsSecretKey  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	mongoURI      = "mongodb://appuser:FixturePassw0rd@db.internal.example.com:27017/app"
	redisURI      = "redis://default:FixtureRedisPass@cache.internal.example.com:6379/0"
	dbPassword    = "FixturePassw0rd"
	encryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	vaultToken    = "hvs.FIXTURE0000000000000000000000000000000000000000000"
)
