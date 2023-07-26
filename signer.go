package secant

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"io"

	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
)

type SignerVerifier interface {
	signature.SignerVerifier
	Cert() []byte
	Chain() []byte
	Bytes() ([]byte, error)
}

type Cosigner interface {
	Cosign(context.Context, io.Reader) (oci.Signature, crypto.PublicKey, error)
}

func NewCosigner(sv SignerVerifier) Cosigner {
	return &cosigner{
		sv: sv,
	}
}

type cosigner struct {
	sv SignerVerifier
}

func (s *cosigner) Cosign(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	payloadBytes, err := io.ReadAll(payload)
	if err != nil {
		return nil, nil, err
	}
	sig, err := s.sv.SignMessage(bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, nil, err
	}

	pk, err := s.sv.PublicKey()
	if err != nil {
		return nil, nil, err
	}

	b64sig := base64.StdEncoding.EncodeToString(sig)
	ociSig, err := static.NewSignature(payloadBytes, b64sig)
	if err != nil {
		return nil, nil, err
	}

	return ociSig, pk, nil
}
