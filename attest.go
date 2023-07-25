package secant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign/attestation"
	cremote "github.com/sigstore/cosign/v2/pkg/cosign/remote"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/cosign/v2/pkg/types"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

type Statement struct {
	Digest  name.Digest
	Type    string
	Payload []byte
}

func NewStatement(digest name.Digest, predicate io.Reader, ptype string) (*Statement, error) {
	h, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return nil, err
	}

	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: predicate,
		Type:      ptype,
		Digest:    h.Hex,
		Repo:      digest.Repository.String(),
	})
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(sh)
	if err != nil {
		return nil, fmt.Errorf("marshaling statement: %w", err)
	}

	return &Statement{
		Digest:  digest,
		Type:    ptype,
		Payload: payload,
	}, nil
}

func Attest(ctx context.Context, statement *Statement, sv *SignerVerifier, rekorClient *client.Rekor) (oci.SignedEntity, error) {
	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)
	dd := cremote.NewDupeDetector(sv)

	signedPayload, err := wrapped.SignMessage(bytes.NewReader(statement.Payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	opts := []static.Option{static.WithLayerMediaType(types.DssePayloadType)}
	if sv.Cert != nil {
		opts = append(opts, static.WithCertChain(sv.Cert, sv.Chain))
	}

	predicateType, err := parsePredicateType(statement.Type)
	if err != nil {
		return nil, err
	}

	predicateTypeAnnotation := map[string]string{
		"predicateType": predicateType,
	}
	// Add predicateType as manifest annotation
	opts = append(opts, static.WithAnnotations(predicateTypeAnnotation))

	// Check whether we should be uploading to the transparency log
	bundle, err := uploadToTlog(ctx, sv, rekorClient, signedPayload)
	if err != nil {
		return nil, fmt.Errorf("uploading to tlog: %w", err)
	}
	opts = append(opts, static.WithBundle(bundle))

	sig, err := static.NewAttestation(signedPayload, opts...)
	if err != nil {
		return nil, err
	}

	// We don't actually need to access the remote entity to attach things to it
	// so we use a placeholder here.
	se := ociremote.SignedUnknown(statement.Digest)

	signOpts := []mutate.SignOption{
		mutate.WithDupeDetector(dd),
	}

	signOpts = append(signOpts, mutate.WithReplaceOp(cremote.NewReplaceOp(predicateType)))

	// Attach the attestation to the entity.
	return mutate.AttachAttestationToEntity(se, sig, signOpts...)
}

func Upload(ctx context.Context, repo name.Repository, se oci.SignedEntity, ropt []remote.Option) error {
	opts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}

	// Publish the attestations associated with this entity
	return ociremote.WriteAttestations(repo, se, opts...)
}
