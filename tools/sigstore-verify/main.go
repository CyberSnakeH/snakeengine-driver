// sigstore-verify — minimal Sigstore signature verifier for SnakeEngine.
//
// This binary is shipped alongside the SnakeEngine self-update flow and
// the snakedrv-updater script. It performs cosign-keyless verification
// of release artifacts using the Sigstore bundle format.
//
// Usage:
//
//	sigstore-verify verify-blob \
//	    --bundle <file>.sigstore \
//	    --certificate-identity-regexp <regex> \
//	    --certificate-oidc-issuer <url> \
//	    [--offline] \
//	    <blob-file>
//
// Exit codes: 0 = valid, 1 = invalid signature, 2 = usage error.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const usage = `sigstore-verify — minimal Sigstore signature verifier

USAGE:
    sigstore-verify verify-blob \
        --bundle <file>.sigstore \
        --certificate-identity-regexp <regex> \
        --certificate-oidc-issuer <url> \
        [--offline] \
        <blob-file>

OPTIONS:
    --bundle <path>                       Sigstore bundle file (.sigstore)
    --certificate-identity-regexp <re>    Required cert SAN identity regex
    --certificate-oidc-issuer <url>       Required OIDC issuer URL
    --offline                             Skip transparency-log lookup
                                          (only use the bundle's embedded
                                          inclusion proof and signed timestamps)

EXIT STATUS:
    0  signature valid and identity matches
    1  signature invalid, identity mismatch, or runtime error
    2  bad usage / argument error
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "verify-blob":
		verifyBlob(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println(versionString())
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "sigstore-verify: unknown subcommand %q\n\n%s",
			os.Args[1], usage)
		os.Exit(2)
	}
}

func verifyBlob(args []string) {
	fs := flag.NewFlagSet("verify-blob", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		bundlePath string
		identityRe string
		oidcIssuer string
		offline    bool
	)
	fs.StringVar(&bundlePath, "bundle", "",
		"Sigstore bundle file (.sigstore)")
	fs.StringVar(&identityRe, "certificate-identity-regexp", "",
		"Required cert SAN identity regex")
	fs.StringVar(&oidcIssuer, "certificate-oidc-issuer", "",
		"Required OIDC issuer URL")
	fs.BoolVar(&offline, "offline", false,
		"Skip Rekor lookup, use embedded proof only")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fmt.Fprint(os.Stderr,
			"sigstore-verify: verify-blob takes exactly one positional argument (the blob path)\n\n")
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if bundlePath == "" || identityRe == "" || oidcIssuer == "" {
		fmt.Fprintln(os.Stderr,
			"sigstore-verify: --bundle, --certificate-identity-regexp, and --certificate-oidc-issuer are all required")
		os.Exit(2)
	}

	blobPath := fs.Arg(0)

	if err := run(context.Background(), runOpts{
		bundlePath: bundlePath,
		blobPath:   blobPath,
		identityRe: identityRe,
		oidcIssuer: oidcIssuer,
		offline:    offline,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "sigstore-verify: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("OK signature valid")
}

type runOpts struct {
	bundlePath string
	blobPath   string
	identityRe string
	oidcIssuer string
	offline    bool
}

func run(ctx context.Context, opt runOpts) error {
	// Sigstore TUF root: lazy-fetched + cached under
	// $XDG_CACHE_HOME/sigstore-go/. The TUF client embeds the public
	// trust anchor so the first fetch is itself authenticated.
	tufOpts := tuf.DefaultOptions()
	// Ten-second timeout: TUF metadata is small, this guards against
	// the verifier hanging on offline hosts.
	tufOpts.WithCachePath(defaultTUFCacheDir())
	tufClient, err := tuf.New(tufOpts)
	if err != nil {
		return fmt.Errorf("tuf client: %w", err)
	}
	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		return fmt.Errorf("trusted root: %w", err)
	}

	// Verifier configuration: require at least one signed timestamp
	// (RFC 3161 or the bundle's signed cert timestamp), at least one
	// observer timestamp, and — unless --offline — at least one
	// transparency-log entry.
	verifierOpts := []verify.VerifierOption{
		verify.WithSignedCertificateTimestamps(1),
		verify.WithObserverTimestamps(1),
	}
	if !opt.offline {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(1))
	}

	sev, err := verify.NewSignedEntityVerifier(trustedRoot, verifierOpts...)
	if err != nil {
		return fmt.Errorf("build verifier: %w", err)
	}

	// Identity policy: require the cert SAN to match identityRe and the
	// OIDC issuer to be exactly oidcIssuer.
	certIdent, err := verify.NewShortCertificateIdentity(
		opt.oidcIssuer, "", "", opt.identityRe)
	if err != nil {
		return fmt.Errorf("build identity policy: %w", err)
	}

	// Load the bundle (.sigstore JSON) and the artifact bytes.
	bun, err := bundle.LoadJSONFromPath(opt.bundlePath)
	if err != nil {
		return fmt.Errorf("load bundle %q: %w", opt.bundlePath, err)
	}

	blob, err := os.Open(opt.blobPath)
	if err != nil {
		return fmt.Errorf("open blob %q: %w", opt.blobPath, err)
	}
	defer blob.Close()

	// `verify.WithArtifact` reads the whole blob into memory. For our
	// release artifacts (a few hundred MB max for an AppImage) that's
	// fine. We still buffer-read so we get a clear error if the blob
	// disappears mid-verify.
	body, err := io.ReadAll(blob)
	if err != nil {
		return fmt.Errorf("read blob: %w", err)
	}

	policy := verify.NewPolicy(
		verify.WithArtifact(bytes.NewReader(body)),
		verify.WithCertificateIdentity(certIdent),
	)

	deadline := time.Now().Add(60 * time.Second)
	verifyCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	result, err := sev.Verify(bun, policy)
	if err != nil {
		return verifyError(err)
	}
	_ = verifyCtx

	if result == nil {
		return errors.New("verifier returned nil result without error — refusing")
	}
	printResult(result)
	return nil
}

// verifyError sands rough edges off sigstore-go errors so the user
// gets an actionable message instead of a wrapped chain.
func verifyError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "certificate identity"):
		return fmt.Errorf("certificate identity mismatch (artifact was signed by a different workflow): %w", err)
	case strings.Contains(msg, "rekor"):
		return fmt.Errorf("transparency-log check failed (try --offline if you trust the bundle): %w", err)
	case strings.Contains(msg, "expired"), strings.Contains(msg, "not yet valid"):
		return fmt.Errorf("signing certificate timestamp out of valid window: %w", err)
	default:
		return fmt.Errorf("verification failed: %w", err)
	}
}

func printResult(r *verify.VerificationResult) {
	if r.Signature == nil {
		return
	}
	if r.Signature.Certificate != nil {
		c := r.Signature.Certificate
		if len(c.SubjectAlternativeName) > 0 {
			fmt.Printf("  Identity: %s\n", c.SubjectAlternativeName)
		}
		if c.Issuer != "" {
			fmt.Printf("  Issuer:   %s\n", c.Issuer)
		}
	}
}

func defaultTUFCacheDir() string {
	if d := os.Getenv("XDG_CACHE_HOME"); d != "" {
		return d + "/sigstore-go"
	}
	if home, err := os.UserHomeDir(); err == nil {
		return home + "/.cache/sigstore-go"
	}
	return os.TempDir() + "/sigstore-go"
}

// versionString is overridden at link time via -ldflags='-X main.version=...'
var version = "dev"

func versionString() string {
	return fmt.Sprintf("sigstore-verify %s", version)
}
