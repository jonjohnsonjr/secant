package fulcio

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"strings"

	"github.com/sigstore/cosign/v2/pkg/cosign"
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

type SignerVerifier struct {
	cert  []byte
	chain []byte
	sct   []byte
	signature.SignerVerifier
}

func (c *SignerVerifier) Cert() []byte {
	return c.cert
}

func (c *SignerVerifier) Chain() []byte {
	return c.chain
}

func (c *SignerVerifier) Bytes() ([]byte, error) {
	return c.cert, nil
}

func NewSigner(ctx context.Context, provider OIDCProvider, fulcioClient api.LegacyClient) (*SignerVerifier, error) {
	sv, err := signerFromNewKey()
	if err != nil {
		return nil, fmt.Errorf("getting signer: %w", err)
	}
	sv, err = keylessSigner(ctx, provider, fulcioClient, sv)
	if err != nil {
		return nil, fmt.Errorf("getting signer: %w", err)
	}

	return sv, nil
}

func signerFromNewKey() (*SignerVerifier, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating cert: %w", err)
	}
	sv, err := signature.LoadECDSASignerVerifier(privKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return &SignerVerifier{
		SignerVerifier: sv,
	}, nil
}

func keylessSigner(ctx context.Context, provider OIDCProvider, fulcioClient api.LegacyClient, sv *SignerVerifier) (*SignerVerifier, error) {
	idToken, err := provider.Provide(ctx, "sigstore")
	if err != nil {
		return nil, err
	}

	fmt.Fprintln(os.Stderr, "Retrieving signed certificate...")

	resp, err := getCertForOauthID(sv, fulcioClient, idToken)
	if err != nil {
		return nil, fmt.Errorf("retrieving cert: %w", err)
	}

	// Grab the PublicKeys for the CTFE, either from tuf or env.
	pubKeys, err := cosign.GetCTLogPubs(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting CTFE public keys: %w", err)
	}

	// verify the sct
	if err := cosign.VerifySCT(ctx, resp.CertPEM, resp.ChainPEM, resp.SCT, pubKeys); err != nil {
		return nil, fmt.Errorf("verifying SCT: %w", err)
	}

	return &SignerVerifier{
		SignerVerifier: sv,
		cert:           resp.CertPEM,
		chain:          resp.ChainPEM,
		sct:            resp.SCT,
	}, nil
}

func getCertForOauthID(sv signature.SignerVerifier, fulcioClient api.LegacyClient, idToken string) (*api.CertificateResponse, error) {
	flow := &oauthflow.StaticTokenGetter{RawToken: idToken}
	tok, err := flow.GetIDToken(nil, oauth2.Config{})
	if err != nil {
		return nil, err
	}

	publicKey, err := sv.PublicKey()
	if err != nil {
		return nil, err
	}
	pubBytes, err := cryptoutils.MarshalPublicKeyToPEM(publicKey)
	if err != nil {
		return nil, err
	}
	// Sign the email address as part of the request
	proof, err := sv.SignMessage(strings.NewReader(tok.Subject))
	if err != nil {
		return nil, err
	}

	cr := api.CertificateRequest{
		PublicKey: api.Key{
			Content: pubBytes,
		},
		SignedEmailAddress: proof,
	}

	return fulcioClient.SigningCert(cr, tok.RawString)
}
