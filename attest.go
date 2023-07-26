package secant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/jonjohnsonjr/secant/intoto"
	"github.com/jonjohnsonjr/secant/tlog"
	"github.com/sigstore/cosign/v2/pkg/cosign/attestation"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	cremote "github.com/sigstore/cosign/v2/pkg/cosign/remote"
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

func Attest(ctx context.Context, statement *Statement, sv SignerVerifier, rekorClient *client.Rekor, ropt []remote.Option) error {
	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)
	dd := cremote.NewDupeDetector(sv)

	signedPayload, err := wrapped.SignMessage(bytes.NewReader(statement.Payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("signing: %w", err)
	}

	opts := []static.Option{static.WithLayerMediaType(types.DssePayloadType)}
	if sv.Cert() != nil {
		opts = append(opts, static.WithCertChain(sv.Cert(), sv.Chain()))
	}

	predicateType, err := parsePredicateType(statement.Type)
	if err != nil {
		return err
	}

	predicateTypeAnnotation := map[string]string{
		"predicateType": predicateType,
	}
	// Add predicateType as manifest annotation
	opts = append(opts, static.WithAnnotations(predicateTypeAnnotation))

	pemBytes, err := sv.Bytes()
	if err != nil {
		return err
	}

	e, err := intoto.Entry(ctx, signedPayload, pemBytes)
	if err != nil {
		return err
	}

	entry, err := tlog.Upload(ctx, rekorClient, e)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)
	bundle := cbundle.EntryToBundle(entry)

	opts = append(opts, static.WithBundle(bundle))

	sig, err := static.NewAttestation(signedPayload, opts...)
	if err != nil {
		return err
	}

	// We don't actually need to access the remote entity to attach things to it
	// so we use a placeholder here.
	se := ociremote.SignedUnknown(statement.Digest)

	signOpts := []mutate.SignOption{
		mutate.WithDupeDetector(dd),
	}

	signOpts = append(signOpts, mutate.WithReplaceOp(cremote.NewReplaceOp(predicateType)))

	// Attach the attestation to the entity.
	se, err = mutate.AttachAttestationToEntity(se, sig, signOpts...)
	if err != nil {
		return err
	}

	// Publish the attestations associated with this entity
	ropts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}
	return ociremote.WriteAttestations(statement.Digest.Repository, se, ropts...)
}

var predicateTypeMap = map[string]string{
	"custom":         "https://cosign.sigstore.dev/attestation/v1",
	"slsaprovenance": "https://slsa.dev/provenance/v0.2",
	"spdx":           "https://spdx.dev/Document",
	"spdxjson":       "https://spdx.dev/Document",
	"cyclonedx":      "https://cyclonedx.org/bom",
	"link":           "https://in-toto.io/Link/v1",
	"vuln":           "https://cosign.sigstore.dev/attestation/vuln/v1",
}

func parsePredicateType(t string) (string, error) {
	uri, ok := predicateTypeMap[t]
	if !ok {
		if _, err := url.ParseRequestURI(t); err != nil {
			return "", fmt.Errorf("invalid predicate type: %s", t)
		}
		uri = t
	}
	return uri, nil
}
