package secant

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/runtime"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/ctutil"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/jonjohnsonjr/secant/tlog"
	"github.com/nozzle/throttler"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	cosignError "github.com/sigstore/cosign/v2/cmd/cosign/errors"
	"github.com/sigstore/cosign/v2/pkg/blob"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	rekor_types "github.com/sigstore/rekor/pkg/types"
	dsse_v001 "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	intoto_v001 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	intoto_v002 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.2"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigopts "github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	"github.com/sigstore/sigstore/pkg/tuf"
)

type VerifyCommand struct {
	options.RegistryOptions
	options.CertVerifyOptions
	Output           string
	RekorURL         string
	Annotations      sigs.AnnotationsMap
	SignatureRef     string
	PayloadRef       string
	LocalImage       bool
	NameOptions      []name.Option
	Offline          bool
	TSACertChainPath string
	IgnoreTlog       bool
	MaxWorkers       int
}

// TODO: Move everything we need into here.
type Verifier struct {
	RekorPubKeys      *tlog.TrustedTransparencyLogPubKeys
	RootCerts         *x509.CertPool
	IntermediateCerts *x509.CertPool
	CTLogPubKeys      *tlog.TrustedTransparencyLogPubKeys
}

func Verify(ctx context.Context, rekorClient *client.Rekor, identities []cosign.Identity, c *VerifyCommand, images []string) (err error) {
	ociremoteOpts, err := c.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}

	co := &cosign.CheckOpts{
		Annotations:        c.Annotations.Annotations,
		RegistryClientOpts: ociremoteOpts,
		SignatureRef:       c.SignatureRef,
		PayloadRef:         c.PayloadRef,
		Identities:         identities,
		Offline:            c.Offline,
		IgnoreTlog:         c.IgnoreTlog,
		MaxWorkers:         c.MaxWorkers,
	}

	// This performs an online fetch of the Rekor public keys, but this is needed
	// for verifying tlog entries (both online and offline).
	co.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
	if err != nil {
		return fmt.Errorf("getting Rekor public keys: %w", err)
	}

	// This performs an online fetch of the Fulcio roots. This is needed
	// for verifying keyless certificates (both online and offline).
	co.RootCerts, err = fulcio.GetRoots()
	if err != nil {
		return fmt.Errorf("getting Fulcio roots: %w", err)
	}
	co.IntermediateCerts, err = fulcio.GetIntermediates()
	if err != nil {
		return fmt.Errorf("getting Fulcio intermediates: %w", err)
	}

	co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
	if err != nil {
		return fmt.Errorf("getting ctlog public keys: %w", err)
	}

	for _, img := range images {
		ref, err := name.ParseReference(img, c.NameOptions...)
		if err != nil {
			return fmt.Errorf("parsing reference: %w", err)
		}

		verified, bundleVerified, err := VerifyImageSignatures(ctx, ref, rekorClient, co)
		if err != nil {
			return cosignError.WrapError(err)
		}

		PrintVerification(ctx, os.Stdout, verified)
	}

	return nil
}

// PrintVerification logs details about the verification to stdout
func PrintVerification(ctx context.Context, w io.Writer, verified []oci.Signature) {
	var outputKeys []payload.SimpleContainerImage
	for _, sig := range verified {
		p, err := sig.Payload()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching payload: %v", err)
			return
		}

		ss := payload.SimpleContainerImage{}
		if err := json.Unmarshal(p, &ss); err != nil {
			fmt.Println("error decoding the payload:", err.Error())
			return
		}

		if cert, err := sig.Cert(); err == nil && cert != nil {
			ce := cosign.CertExtensions{Cert: cert}
			if ss.Optional == nil {
				ss.Optional = make(map[string]interface{})
			}
			ss.Optional["Subject"] = sigs.CertSubject(cert)
			if issuerURL := ce.GetIssuer(); issuerURL != "" {
				ss.Optional["Issuer"] = issuerURL
				ss.Optional[cosign.CertExtensionOIDCIssuer] = issuerURL
			}
			if githubWorkflowTrigger := ce.GetCertExtensionGithubWorkflowTrigger(); githubWorkflowTrigger != "" {
				ss.Optional[cosign.CertExtensionMap[cosign.CertExtensionGithubWorkflowTrigger]] = githubWorkflowTrigger
				ss.Optional[cosign.CertExtensionGithubWorkflowTrigger] = githubWorkflowTrigger
			}

			if githubWorkflowSha := ce.GetExtensionGithubWorkflowSha(); githubWorkflowSha != "" {
				ss.Optional[cosign.CertExtensionMap[cosign.CertExtensionGithubWorkflowSha]] = githubWorkflowSha
				ss.Optional[cosign.CertExtensionGithubWorkflowSha] = githubWorkflowSha
			}
			if githubWorkflowName := ce.GetCertExtensionGithubWorkflowName(); githubWorkflowName != "" {
				ss.Optional[cosign.CertExtensionMap[cosign.CertExtensionGithubWorkflowName]] = githubWorkflowName
				ss.Optional[cosign.CertExtensionGithubWorkflowName] = githubWorkflowName
			}

			if githubWorkflowRepository := ce.GetCertExtensionGithubWorkflowRepository(); githubWorkflowRepository != "" {
				ss.Optional[cosign.CertExtensionMap[cosign.CertExtensionGithubWorkflowRepository]] = githubWorkflowRepository
				ss.Optional[cosign.CertExtensionGithubWorkflowRepository] = githubWorkflowRepository
			}

			if githubWorkflowRef := ce.GetCertExtensionGithubWorkflowRef(); githubWorkflowRef != "" {
				ss.Optional[cosign.CertExtensionMap[cosign.CertExtensionGithubWorkflowRef]] = githubWorkflowRef
				ss.Optional[cosign.CertExtensionGithubWorkflowRef] = githubWorkflowRef
			}
		}
		if bundle, err := sig.Bundle(); err == nil && bundle != nil {
			if ss.Optional == nil {
				ss.Optional = make(map[string]interface{})
			}
			ss.Optional["Bundle"] = bundle
		}
		if rfc3161Timestamp, err := sig.RFC3161Timestamp(); err == nil && rfc3161Timestamp != nil {
			if ss.Optional == nil {
				ss.Optional = make(map[string]interface{})
			}
			ss.Optional["RFC3161Timestamp"] = rfc3161Timestamp
		}

		outputKeys = append(outputKeys, ss)
	}

	b, err := json.Marshal(outputKeys)
	if err != nil {
		fmt.Println("error when generating the output:", err.Error())
		return
	}

	fmt.Fprintf(w, "\n%s\n", string(b))
}

func loadCertChainFromFileOrURL(path string) ([]*x509.Certificate, error) {
	pems, err := blob.LoadFileOrURL(path)
	if err != nil {
		return nil, err
	}
	certs, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(pems))
	if err != nil {
		return nil, err
	}
	return certs, nil
}

func VerifyImageSignatures(ctx context.Context, signedImgRef name.Reference, rekorClient *client.Rekor, co *CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
	// This is a carefully optimized sequence for fetching the signatures of the
	// entity that minimizes registry requests when supplied with a digest input
	digest, err := ociremote.ResolveDigest(signedImgRef, co.RegistryClientOpts...)
	if err != nil {
		if terr := (&transport.Error{}); errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
			return nil, false, fmt.Errorf("image tag not found: %w", err)
		}
		return nil, false, err
	}
	h, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return nil, false, err
	}

	st, err := ociremote.SignatureTag(digest, co.RegistryClientOpts...)
	if err != nil {
		return nil, false, err
	}
	sigs, err := ociremote.Signatures(st, co.RegistryClientOpts...)
	if err != nil {
		return nil, false, err
	}

	return verifySignatures(ctx, sigs, h, rekorClient, co)
}

func verifySignatures(ctx context.Context, sigs oci.Signatures, h v1.Hash, rekorClient *client.Rekor, co *CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
	sl, err := sigs.Get()
	if err != nil {
		return nil, false, err
	}

	if len(sl) == 0 {
		return nil, false, errors.New("no matching signatures")
	}

	signatures := make([]oci.Signature, len(sl))
	bundlesVerified := make([]bool, len(sl))

	// TODO: Not hardcoded to 10?
	workers := 10
	t := throttler.New(workers, len(sl))
	for i, sig := range sl {
		go func(sig oci.Signature, index int) {
			sig, err := static.Copy(sig)
			if err != nil {
				t.Done(err)
				return
			}
			verified, err := verifyInternal(ctx, sig, h, rekorClient, co)
			bundlesVerified[index] = verified
			if err != nil {
				t.Done(err)
				return
			}
			signatures[index] = sig

			t.Done(nil)
		}(sig, i)

		// wait till workers are available
		t.Throttle()
	}

	for _, s := range signatures {
		if s != nil {
			checkedSignatures = append(checkedSignatures, s)
		}
	}

	for _, verified := range bundlesVerified {
		bundleVerified = bundleVerified || verified
	}

	if len(checkedSignatures) == 0 {
		var combinedErrors []string
		for _, err := range t.Errs() {
			combinedErrors = append(combinedErrors, err.Error())
		}
		// TODO: ErrNoMatchingSignatures.Unwrap should return []error,
		// or we should replace "...%s" strings.Join with "...%w", errors.Join.
		return nil, false, fmt.Errorf("no matching signatures: %s", strings.Join(combinedErrors, "\n "))
	}

	return checkedSignatures, bundleVerified, nil
}

func verifyInternal(ctx context.Context, sig oci.Signature, h v1.Hash, rekorClient *client.Rekor, co *CheckOpts) (bundleVerified bool, err error) {
	var acceptableRFC3161Time, acceptableRekorBundleTime *time.Time // Timestamps for the signature we accept, or nil if not applicable.

	bundleVerified, err = VerifyBundle(sig, co)
	if err != nil {
		return false, fmt.Errorf("error verifying bundle: %w", err)
	}

	if bundleVerified {
		// Update with the verified bundle's integrated time.
		t, err := getBundleIntegratedTime(sig)
		if err != nil {
			return false, fmt.Errorf("error getting bundle integrated time: %w", err)
		}
		acceptableRekorBundleTime = &t
	} else {
		// If the --offline flag was specified, fail here. bundleVerified returns false with
		// no error when there was no bundle provided.
		if co.Offline {
			return false, fmt.Errorf("offline verification failed")
		}

		pemBytes, err := keyBytes(sig, co)
		if err != nil {
			return false, err
		}

		e, err := tlogValidateEntry(ctx, rekorClient, co.RekorPubKeys, sig, pemBytes)
		if err != nil {
			return false, err
		}
		t := time.Unix(*e.IntegratedTime, 0)
		acceptableRekorBundleTime = &t
	}

	// If we don't have a public key to check against, we can try a root cert.
	cert, err := sig.Cert()
	if err != nil {
		return false, err
	}
	if cert == nil {
		return false, fmt.Errorf("no certificate found on signature")
	}
	// Create a certificate pool for intermediate CA certificates, excluding the root
	chain, err := sig.Chain()
	if err != nil {
		return false, err
	}
	// If there is no chain annotation present, we preserve the pools set in the CheckOpts.
	if len(chain) > 0 {
		if len(chain) == 1 {
			co.IntermediateCerts = nil
		} else if co.IntermediateCerts == nil {
			// If the intermediate certs have not been loaded in by TUF
			pool := x509.NewCertPool()
			for _, cert := range chain[:len(chain)-1] {
				pool.AddCert(cert)
			}
			co.IntermediateCerts = pool
		}
	}
	verifier, err := ValidateAndUnpackCert(cert, co)
	if err != nil {
		return false, err
	}

	// 1. Perform cryptographic verification of the signature using the certificate's public key.
	b64sig, err := sig.Base64Signature()
	if err != nil {
		return false, err
	}
	signature, err := base64.StdEncoding.DecodeString(b64sig)
	if err != nil {
		return false, err
	}
	payload, err := sig.Payload()
	if err != nil {
		return false, err
	}
	if err := verifier.VerifySignature(bytes.NewReader(signature), bytes.NewReader(payload), sigopts.WithContext(ctx)); err != nil {
		return false, err
	}

	// We can't check annotations without claims, both require unmarshalling the payload.
	mt, err := sig.MediaType()
	if err != nil {
		return false, err
	}

	if mt == "application/vnd.dsse.envelope.v1+json" {
		// This function references intoto but it assumes a dsse wrapper.
		if err := cosign.IntotoSubjectClaimVerifier(sig, h, co.Annotations); err != nil {
			return false, err
		}
	} else {
		// We're going to assume "simple" otherwise.
		if err := cosign.SimpleClaimVerifier(sig, h, co.Annotations); err != nil {
			return false, err
		}
	}

	// 2. if a certificate was used, verify the certificate expiration against a time
	if cert != nil {
		// use the provided Rekor bundle or RFC3161 timestamp to check certificate expiration
		expirationChecked := false

		if acceptableRFC3161Time != nil {
			// Verify the cert against the timestamp time.
			if err := CheckExpiry(cert, *acceptableRFC3161Time); err != nil {
				return false, fmt.Errorf("checking expiry on certificate with timestamp: %w", err)
			}
			expirationChecked = true
		}

		if acceptableRekorBundleTime != nil {
			if err := CheckExpiry(cert, *acceptableRekorBundleTime); err != nil {
				return false, fmt.Errorf("checking expiry on certificate with bundle: %w", err)
			}
			expirationChecked = true
		}

		// if no timestamp has been provided, use the current time
		if !expirationChecked {
			if err := CheckExpiry(cert, time.Now()); err != nil {
				// If certificate is expired and not signed timestamp was provided then error the following message. Otherwise throw an expiration error.
				if co.IgnoreTlog && acceptableRFC3161Time == nil {
					return false, fmt.Errorf("expected a signed timestamp to verify an expired certificate")
				}
				return false, fmt.Errorf("checking expiry on certificate with bundle: %w", err)
			}
		}
	}

	return bundleVerified, nil
}

func CheckExpiry(cert *x509.Certificate, it time.Time) error {
	ft := func(t time.Time) string {
		return t.Format(time.RFC3339)
	}
	if cert.NotAfter.Before(it) {
		return fmt.Errorf("certificate expired before signatures were entered in log: %s is before %s", ft(cert.NotAfter), ft(it))
	}
	if cert.NotBefore.After(it) {
		return fmt.Errorf("certificate was issued after signatures were entered in log: %s is after %s", ft(cert.NotAfter), ft(it))
	}
	return nil
}

func getBundleIntegratedTime(sig oci.Signature) (time.Time, error) {
	bundle, err := sig.Bundle()
	if err != nil {
		return time.Now(), err
	} else if bundle == nil {
		return time.Now(), nil
	}
	return time.Unix(bundle.Payload.IntegratedTime, 0), nil
}

func ValidateAndUnpackCert(cert *x509.Certificate, co *CheckOpts) (signature.Verifier, error) {
	verifier, err := signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate found on signature: %w", err)
	}

	// Handle certificates where the Subject Alternative Name is not set to a supported
	// GeneralName (RFC 5280 4.2.1.6). Go only supports DNS, IP addresses, email addresses,
	// or URIs as SANs. Fulcio can issue a certificate with an OtherName GeneralName, so
	// remove the unhandled critical SAN extension before verifying.
	if len(cert.UnhandledCriticalExtensions) > 0 {
		var unhandledExts []asn1.ObjectIdentifier
		for _, oid := range cert.UnhandledCriticalExtensions {
			if !oid.Equal(cryptoutils.SANOID) {
				unhandledExts = append(unhandledExts, oid)
			}
		}
		cert.UnhandledCriticalExtensions = unhandledExts
	}

	// Now verify the cert, then the signature.
	chains, err := TrustedCert(cert, co.RootCerts, co.IntermediateCerts)
	if err != nil {
		return nil, err
	}

	err = CheckCertificatePolicy(cert, co)
	if err != nil {
		return nil, err
	}

	contains, err := ContainsSCT(cert.Raw)
	if err != nil {
		return nil, err
	}
	if !contains && len(co.SCT) == 0 {
		return nil, &VerificationFailure{
			fmt.Errorf("certificate does not include required embedded SCT and no detached SCT was set"),
		}
	}
	// handle if chains has more than one chain - grab first and print message
	if len(chains) > 1 {
		fmt.Fprintf(os.Stderr, "**Info** Multiple valid certificate chains found. Selecting the first to verify the SCT.\n")
	}
	if contains {
		if err := VerifyEmbeddedSCT(context.Background(), chains[0], co.CTLogPubKeys); err != nil {
			return nil, err
		}
	} else {
		chain := chains[0]
		if len(chain) < 2 {
			return nil, errors.New("certificate chain must contain at least a certificate and its issuer")
		}
		certPEM, err := cryptoutils.MarshalCertificateToPEM(chain[0])
		if err != nil {
			return nil, err
		}
		chainPEM, err := cryptoutils.MarshalCertificatesToPEM(chain[1:])
		if err != nil {
			return nil, err
		}
		if err := VerifySCT(context.Background(), certPEM, chainPEM, co.SCT, co.CTLogPubKeys); err != nil {
			return nil, err
		}
	}

	return verifier, nil
}

func TrustedCert(cert *x509.Certificate, roots *x509.CertPool, intermediates *x509.CertPool) ([][]*x509.Certificate, error) {
	chains, err := cert.Verify(x509.VerifyOptions{
		// THIS IS IMPORTANT: WE DO NOT CHECK TIMES HERE
		// THE CERTIFICATE IS TREATED AS TRUSTED FOREVER
		// WE CHECK THAT THE SIGNATURES WERE CREATED DURING THIS WINDOW
		CurrentTime:   cert.NotBefore,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("cert verification failed: %w. Check your TUF root (see cosign initialize) or set a custom root with env var SIGSTORE_ROOT_FILE", err)
	}
	return chains, nil
}

func CheckCertificatePolicy(cert *x509.Certificate, co *CheckOpts) error {
	ce := cosign.CertExtensions{Cert: cert}

	if err := validateCertExtensions(ce, co); err != nil {
		return err
	}
	oidcIssuer := ce.GetIssuer()
	sans := getSubjectAlternateNames(cert)
	// If there are identities given, go through them and if one of them
	// matches, call that good, otherwise, return an error.
	if len(co.Identities) > 0 {
		for _, identity := range co.Identities {
			issuerMatches := false
			switch {
			// Check the issuer first
			case identity.IssuerRegExp != "":
				if regex, err := regexp.Compile(identity.IssuerRegExp); err != nil {
					return fmt.Errorf("malformed issuer in identity: %s : %w", identity.IssuerRegExp, err)
				} else if regex.MatchString(oidcIssuer) {
					issuerMatches = true
				}
			case identity.Issuer != "":
				if identity.Issuer == oidcIssuer {
					issuerMatches = true
				}
			default:
				// No issuer constraint on this identity, so checks out
				issuerMatches = true
			}

			// Then the subject
			subjectMatches := false
			switch {
			case identity.SubjectRegExp != "":
				regex, err := regexp.Compile(identity.SubjectRegExp)
				if err != nil {
					return fmt.Errorf("malformed subject in identity: %s : %w", identity.SubjectRegExp, err)
				}
				for _, san := range sans {
					if regex.MatchString(san) {
						subjectMatches = true
						break
					}
				}
			case identity.Subject != "":
				for _, san := range sans {
					if san == identity.Subject {
						subjectMatches = true
						break
					}
				}
			default:
				// No subject constraint on this identity, so checks out
				subjectMatches = true
			}
			if subjectMatches && issuerMatches {
				// If both issuer / subject match, return verified
				return nil
			}
		}
		return fmt.Errorf("none of the expected identities matched what was in the certificate, got subjects [%s] with issuer %s", strings.Join(sans, ", "), oidcIssuer)
	}
	return nil
}

func ContainsSCT(cert []byte) (bool, error) {
	embeddedSCTs, err := x509util.ParseSCTsFromCertificate(cert)
	if err != nil {
		return false, err
	}
	if len(embeddedSCTs) != 0 {
		return true, nil
	}
	return false, nil
}

func VerifyBundle(sig oci.Signature, co *CheckOpts) (bool, error) {
	bundle, err := sig.Bundle()
	if err != nil {
		return false, err
	} else if bundle == nil {
		return false, nil
	}

	if co.RekorPubKeys == nil || co.RekorPubKeys.Keys == nil {
		return false, errors.New("no trusted rekor public keys provided")
	}
	// Make sure all the rekorPubKeys are ecsda.PublicKeys
	for k, v := range co.RekorPubKeys.Keys {
		if _, ok := v.PubKey.(*ecdsa.PublicKey); !ok {
			return false, fmt.Errorf("rekor Public key for LogID %s is not type ecdsa.PublicKey", k)
		}
	}

	if err := compareSigs(bundle.Payload.Body.(string), sig); err != nil {
		return false, err
	}

	if err := comparePublicKey(bundle.Payload.Body.(string), sig); err != nil {
		return false, err
	}

	pubKey, ok := co.RekorPubKeys.Keys[bundle.Payload.LogID]
	if !ok {
		return false, fmt.Errorf("verifying bundle: rekor log public key not found for payload")
	}
	err = VerifySET(bundle.Payload, bundle.SignedEntryTimestamp, pubKey.PubKey.(*ecdsa.PublicKey))
	if err != nil {
		return false, err
	}
	if pubKey.Status != tuf.Active {
		fmt.Fprintf(os.Stderr, "**Info** Successfully verified Rekor entry using an expired verification key\n")
	}

	payload, err := sig.Payload()
	if err != nil {
		return false, fmt.Errorf("reading payload: %w", err)
	}
	signature, err := sig.Base64Signature()
	if err != nil {
		return false, fmt.Errorf("reading base64signature: %w", err)
	}

	alg, bundlehash, err := bundleHash(bundle.Payload.Body.(string), signature)
	h := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(h[:])

	if alg != "sha256" || bundlehash != payloadHash {
		return false, fmt.Errorf("matching bundle to payload: %w", err)
	}
	return true, nil
}

func keyBytes(sig oci.Signature) ([]byte, error) {
	cert, err := sig.Cert()
	if err != nil {
		return nil, err
	}
	return cryptoutils.MarshalCertificateToPEM(cert)
}

func tlogValidateEntry(ctx context.Context, client *client.Rekor, rekorPubKeys *tlog.TrustedTransparencyLogPubKeys, sig oci.Signature, pem []byte) (*models.LogEntryAnon, error) {
	b64sig, err := sig.Base64Signature()
	if err != nil {
		return nil, err
	}
	payload, err := sig.Payload()
	if err != nil {
		return nil, err
	}
	tlogEntries, err := FindTlogEntry(ctx, client, b64sig, payload, pem)
	if err != nil {
		return nil, err
	}
	if len(tlogEntries) == 0 {
		return nil, fmt.Errorf("no valid tlog entries found with proposed entry")
	}
	// Always return the earliest integrated entry. That
	// always suffices for verification of signature time.
	var earliestLogEntry models.LogEntryAnon
	var earliestLogEntryTime *time.Time
	entryVerificationErrs := make([]string, 0)
	for _, e := range tlogEntries {
		entry := e
		if err := tlog.VerifyTLogEntryOffline(ctx, &entry, rekorPubKeys); err != nil {
			entryVerificationErrs = append(entryVerificationErrs, err.Error())
			continue
		}
		entryTime := time.Unix(*entry.IntegratedTime, 0)
		if earliestLogEntryTime == nil || entryTime.Before(*earliestLogEntryTime) {
			earliestLogEntryTime = &entryTime
			earliestLogEntry = entry
		}
	}
	if earliestLogEntryTime == nil {
		return nil, fmt.Errorf("no valid tlog entries found %s", strings.Join(entryVerificationErrs, ", "))
	}
	return &earliestLogEntry, nil
}

func VerifySET(bundlePayload cbundle.RekorPayload, signature []byte, pub *ecdsa.PublicKey) error {
	contents, err := json.Marshal(bundlePayload)
	if err != nil {
		return fmt.Errorf("marshaling: %w", err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(contents)
	if err != nil {
		return fmt.Errorf("canonicalizing: %w", err)
	}

	// verify the SET against the public key
	hash := sha256.Sum256(canonicalized)
	if !ecdsa.VerifyASN1(pub, hash[:], signature) {
		return fmt.Errorf("unable to verify SET")
	}
	return nil
}

func compareSigs(bundleBody string, sig oci.Signature) error {
	// TODO(nsmith5): modify function signature to make it more clear _why_
	// we've returned nil (there are several reasons possible here).
	actualSig, err := sig.Base64Signature()
	if err != nil {
		return fmt.Errorf("base64 signature: %w", err)
	}
	if actualSig == "" {
		// NB: empty sig means this is an attestation
		return nil
	}
	bundleSignature, err := bundleSig(bundleBody)
	if err != nil {
		return fmt.Errorf("failed to extract signature from bundle: %w", err)
	}
	if bundleSignature == "" {
		return nil
	}
	if bundleSignature != actualSig {
		return fmt.Errorf("signature in bundle does not match signature being verified")
	}
	return nil
}

func comparePublicKey(bundleBody string, sig oci.Signature) error {
	pemBytes, err := keyBytes(sig)
	if err != nil {
		return err
	}

	bundleKey, err := bundleKey(bundleBody)
	if err != nil {
		return fmt.Errorf("failed to extract key from bundle: %w", err)
	}

	decodeSecond, err := base64.StdEncoding.DecodeString(bundleKey)
	if err != nil {
		return fmt.Errorf("decoding base64 string %s", bundleKey)
	}

	// Compare the PEM bytes, to ignore spurious newlines in the public key bytes.
	pemFirst, rest := pem.Decode(pemBytes)
	if len(rest) > 0 {
		return fmt.Errorf("unexpected PEM block: %s", rest)
	}
	pemSecond, rest := pem.Decode(decodeSecond)
	if len(rest) > 0 {
		return fmt.Errorf("unexpected PEM block: %s", rest)
	}

	if !bytes.Equal(pemFirst.Bytes, pemSecond.Bytes) {
		return fmt.Errorf("comparing public key PEMs, expected %s, got %s",
			pemBytes, decodeSecond)
	}

	return nil
}

func bundleKey(bundleBody string) (string, error) {
	ei, err := extractEntryImpl(bundleBody)
	if err != nil {
		return "", err
	}

	switch entry := ei.(type) {
	case *dsse_v001.V001Entry:
		if len(entry.DSSEObj.Signatures) > 1 {
			return "", errors.New("multiple signatures on DSSE envelopes are not currently supported")
		}
		return entry.DSSEObj.Signatures[0].Verifier.String(), nil
	case *hashedrekord_v001.V001Entry:
		return entry.HashedRekordObj.Signature.PublicKey.Content.String(), nil
	case *intoto_v001.V001Entry:
		return entry.IntotoObj.PublicKey.String(), nil
	case *intoto_v002.V002Entry:
		if len(entry.IntotoObj.Content.Envelope.Signatures) > 1 {
			return "", errors.New("multiple signatures on DSSE envelopes are not currently supported")
		}
		return entry.IntotoObj.Content.Envelope.Signatures[0].PublicKey.String(), nil
	case *rekord_v001.V001Entry:
		return entry.RekordObj.Signature.PublicKey.Content.String(), nil
	default:
		return "", errors.New("unsupported type")
	}
}

func extractEntryImpl(bundleBody string) (rekor_types.EntryImpl, error) {
	pe, err := models.UnmarshalProposedEntry(base64.NewDecoder(base64.StdEncoding, strings.NewReader(bundleBody)), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	return rekor_types.UnmarshalEntry(pe)
}

func VerifySCT(_ context.Context, certPEM, chainPEM, rawSCT []byte, pubKeys *tlog.TrustedTransparencyLogPubKeys) error {
	if pubKeys == nil || len(pubKeys.Keys) == 0 {
		return errors.New("none of the CTFE keys have been found")
	}

	// parse certificate and chain
	cert, err := x509util.CertificateFromPEM(certPEM)
	if err != nil {
		return err
	}
	certChain, err := x509util.CertificatesFromPEM(chainPEM)
	if err != nil {
		return err
	}
	if len(certChain) == 0 {
		return errors.New("no certificate chain found")
	}

	// fetch embedded SCT if present
	embeddedSCTs, err := x509util.ParseSCTsFromCertificate(certPEM)
	if err != nil {
		return err
	}
	// SCT must be either embedded or in header
	if len(embeddedSCTs) == 0 && len(rawSCT) == 0 {
		return errors.New("no SCT found")
	}

	// check SCT embedded in certificate
	if len(embeddedSCTs) != 0 {
		for _, sct := range embeddedSCTs {
			pubKeyMetadata, err := getCTPublicKey(sct, pubKeys)
			if err != nil {
				return err
			}
			err = ctutil.VerifySCT(pubKeyMetadata.PubKey, []*ctx509.Certificate{cert, certChain[0]}, sct, true)
			if err != nil {
				return fmt.Errorf("error verifying embedded SCT")
			}
			if pubKeyMetadata.Status != tuf.Active {
				fmt.Fprintf(os.Stderr, "**Info** Successfully verified embedded SCT using an expired verification key\n")
			}
		}
		return nil
	}

	// check SCT in response header
	var addChainResp ct.AddChainResponse
	if err := json.Unmarshal(rawSCT, &addChainResp); err != nil {
		return fmt.Errorf("unmarshal")
	}
	sct, err := addChainResp.ToSignedCertificateTimestamp()
	if err != nil {
		return err
	}
	pubKeyMetadata, err := getCTPublicKey(sct, pubKeys)
	if err != nil {
		return err
	}
	err = ctutil.VerifySCT(pubKeyMetadata.PubKey, []*ctx509.Certificate{cert}, sct, false)
	if err != nil {
		return fmt.Errorf("error verifying SCT")
	}
	if pubKeyMetadata.Status != tuf.Active {
		fmt.Fprintf(os.Stderr, "**Info** Successfully verified SCT using an expired verification key\n")
	}
	return nil
}

func getCTPublicKey(sct *ct.SignedCertificateTimestamp,
	pubKeys *tlog.TrustedTransparencyLogPubKeys) (*tlog.TransparencyLogPubKey, error) {
	keyID := hex.EncodeToString(sct.LogID.KeyID[:])
	pubKeyMetadata, ok := pubKeys.Keys[keyID]
	if !ok {
		return nil, errors.New("ctfe public key not found for payload. Check your TUF root (see cosign initialize) or set a custom key with env var SIGSTORE_CT_LOG_PUBLIC_KEY_FILE")
	}
	return &pubKeyMetadata, nil
}

func getSubjectAlternateNames(cert *x509.Certificate) []string {
	sans := []string{}
	sans = append(sans, cert.DNSNames...)
	sans = append(sans, cert.EmailAddresses...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}
	// ignore error if there's no OtherName SAN
	otherName, _ := cryptoutils.UnmarshalOtherNameSAN(cert.Extensions)
	if len(otherName) > 0 {
		sans = append(sans, otherName)
	}
	return sans
}

func bundleHash(bundleBody, _ string) (string, string, error) {
	ei, err := extractEntryImpl(bundleBody)
	if err != nil {
		return "", "", err
	}

	switch entry := ei.(type) {
	case *dsse_v001.V001Entry:
		return *entry.DSSEObj.EnvelopeHash.Algorithm, *entry.DSSEObj.EnvelopeHash.Value, nil
	case *hashedrekord_v001.V001Entry:
		return *entry.HashedRekordObj.Data.Hash.Algorithm, *entry.HashedRekordObj.Data.Hash.Value, nil
	case *intoto_v001.V001Entry:
		return *entry.IntotoObj.Content.Hash.Algorithm, *entry.IntotoObj.Content.Hash.Value, nil
	case *intoto_v002.V002Entry:
		return *entry.IntotoObj.Content.Hash.Algorithm, *entry.IntotoObj.Content.Hash.Value, nil
	case *rekord_v001.V001Entry:
		return *entry.RekordObj.Data.Hash.Algorithm, *entry.RekordObj.Data.Hash.Value, nil
	default:
		return "", "", errors.New("unsupported type")
	}
}

func bundleSig(bundleBody string) (string, error) {
	ei, err := extractEntryImpl(bundleBody)
	if err != nil {
		return "", err
	}

	switch entry := ei.(type) {
	case *dsse_v001.V001Entry:
		if len(entry.DSSEObj.Signatures) > 1 {
			return "", errors.New("multiple signatures on DSSE envelopes are not currently supported")
		}
		return *entry.DSSEObj.Signatures[0].Signature, nil
	case *hashedrekord_v001.V001Entry:
		return entry.HashedRekordObj.Signature.Content.String(), nil
	case *intoto_v002.V002Entry:
		if len(entry.IntotoObj.Content.Envelope.Signatures) > 1 {
			return "", errors.New("multiple signatures on DSSE envelopes are not currently supported")
		}
		return entry.IntotoObj.Content.Envelope.Signatures[0].Sig.String(), nil
	case *rekord_v001.V001Entry:
		return entry.RekordObj.Signature.Content.String(), nil
	default:
		return "", errors.New("unsupported type")
	}
}
