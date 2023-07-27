package fulcio

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/x509"

	"github.com/google/certificate-transparency-go/x509util"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
	"golang.org/x/oauth2"
)

// OIDCProvider is what providers need to implement to participate in furnishing OIDC tokens.
type OIDCProvider interface {
	// Enabled returns true if the provider is enabled.
	Enabled(ctx context.Context) bool

	// Provide returns an OIDC token scoped to the provided audience.
	Provide(ctx context.Context, audience string) (string, error)
}

// SignerVerifier implements types.CosignerSignerVerifier using "keyless" signatures.
// If its signing certificate expires, it will refresh it by requesting a new cert from fulcio
// using the same key.
type SignerVerifier struct {
	inner        signature.SignerVerifier
	provider     OIDCProvider
	fulcioClient api.LegacyClient

	// Protects these fields from mutating from refresh().
	sync.Mutex
	cert    *x509.Certificate
	certPEM []byte
	chain   []byte
	sct     []byte
}

func (c *SignerVerifier) Cert() []byte {
	return c.certPEM
}

func (c *SignerVerifier) Chain() []byte {
	return c.chain
}

func (c *SignerVerifier) Bytes() ([]byte, error) {
	return c.certPEM, nil
}

// NewSigner returns a "keyless" fulcio signer.
func NewSigner(ctx context.Context, provider OIDCProvider, fulcioClient api.LegacyClient) (*SignerVerifier, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating cert: %w", err)
	}

	inner, err := signature.LoadECDSASignerVerifier(privKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	sv := &SignerVerifier{
		inner:        inner,
		provider:     provider,
		fulcioClient: fulcioClient,
	}

	return sv, sv.refresh(ctx)
}

func (sv *SignerVerifier) refresh(ctx context.Context) error {
	if time.Now().Before(sv.cert.NotAfter) {
		return nil
	}

	idToken, err := sv.provider.Provide(ctx, "sigstore")
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Retrieving signed certificate...")

	flow := &oauthflow.StaticTokenGetter{RawToken: idToken}
	tok, err := flow.GetIDToken(nil, oauth2.Config{})
	if err != nil {
		return err
	}

	publicKey, err := sv.inner.PublicKey()
	if err != nil {
		return err
	}
	pubBytes, err := cryptoutils.MarshalPublicKeyToPEM(publicKey)
	if err != nil {
		return err
	}

	// Sign the email address as part of the request
	proof, err := sv.inner.SignMessage(strings.NewReader(tok.Subject))
	if err != nil {
		return err
	}

	cr := api.CertificateRequest{
		PublicKey: api.Key{
			Content: pubBytes,
		},
		SignedEmailAddress: proof,
	}

	resp, err := sv.fulcioClient.SigningCert(cr, tok.RawString)
	if err != nil {
		return fmt.Errorf("retrieving cert: %w", err)
	}

	// Grab the PublicKeys for the CTFE, either from tuf or env.
	pubKeys, err := cosign.GetCTLogPubs(ctx)
	if err != nil {
		return fmt.Errorf("getting CTFE public keys: %w", err)
	}

	// verify the sct
	if err := cosign.VerifySCT(ctx, resp.CertPEM, resp.ChainPEM, resp.SCT, pubKeys); err != nil {
		return fmt.Errorf("verifying SCT: %w", err)
	}

	cert, err := x509util.CertificateFromPEM(resp.CertPEM)
	if err != nil {
		return fmt.Errorf("parsing cert PEM: %w", err)
	}

	sv.cert = cert
	sv.certPEM = resp.CertPEM
	sv.chain = resp.ChainPEM
	sv.sct = resp.SCT

	return nil
}

func (sv *SignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	sv.Lock()
	defer sv.Unlock()

	if time.Now().After(sv.cert.NotAfter) {
		// If we are passed a signature.WithContext option, this will pull it out.
		// Otherwise, it defaults to context.Background().
		ctx := context.Background()
		for _, opt := range opts {
			opt.ApplyContext(&ctx)
		}

		if err := sv.refresh(ctx); err != nil {
			return nil, fmt.Errorf("refreshing fulcio cert: %w", err)
		}
	}

	return sv.inner.SignMessage(message, opts...)
}

func (sv *SignerVerifier) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	return sv.inner.VerifySignature(signature, message, opts...)
}

func (sv *SignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return sv.inner.PublicKey(opts...)
}

// Cosign implements Cosigner.
func (sv *SignerVerifier) Cosign(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	sv.Lock()
	defer sv.Unlock()

	if time.Now().After(sv.cert.NotAfter) {
		if err := sv.refresh(ctx); err != nil {
			return nil, nil, fmt.Errorf("refreshing fulcio cert: %w", err)
		}
	}

	payloadBytes, err := io.ReadAll(payload)
	if err != nil {
		return nil, nil, err
	}
	signed, err := sv.inner.SignMessage(bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, nil, err
	}

	pub, err := sv.inner.PublicKey()
	if err != nil {
		return nil, nil, err
	}

	sig, err := static.NewSignature(payloadBytes, base64.StdEncoding.EncodeToString(signed))
	if err != nil {
		return nil, nil, err
	}

	// TODO(dekkagaijin): move the fulcio SignerVerifier logic here
	newSig, err := mutate.Signature(sig, mutate.WithCertChain(sv.certPEM, sv.chain))
	if err != nil {
		return nil, nil, err
	}

	return newSig, pub, nil
}
