package secant

import (
	"bytes"
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/jonjohnsonjr/secant/fulcio"
	"github.com/jonjohnsonjr/secant/rekor"
	cremote "github.com/sigstore/cosign/v2/pkg/cosign/remote"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/walk"
	"github.com/sigstore/rekor/pkg/generated/client"
	sigPayload "github.com/sigstore/sigstore/pkg/signature/payload"
)

func Sign(ctx context.Context, annotations map[string]interface{}, sv SignerVerifier, rekorClient *client.Rekor, imgs []string, ropt []remote.Option) error {
	dd := cremote.NewDupeDetector(sv)
	cs := NewCosigner(sv)
	cs = fulcio.NewCosigner(cs, sv.Cert(), sv.Chain())
	cs = rekor.NewCosigner(cs, rekorClient)

	opts := []ociremote.Option{ociremote.WithRemoteOptions(ropt...)}

	for _, inputImg := range imgs {
		ref, err := name.ParseReference(inputImg)
		if err != nil {
			return err
		}

		se, err := ociremote.SignedEntity(ref, opts...)
		if err != nil {
			return fmt.Errorf("accessing entity: %w", err)
		}

		if err := walk.SignedEntity(ctx, se, func(ctx context.Context, se oci.SignedEntity) error {
			// Get the digest for this entity in our walk.
			d, err := se.(interface{ Digest() (v1.Hash, error) }).Digest()
			if err != nil {
				return fmt.Errorf("computing digest: %w", err)
			}
			digest := ref.Context().Digest(d.String())
			if err := signDigest(ctx, digest, annotations, dd, cs, se, opts); err != nil {
				return fmt.Errorf("signing digest: %w", err)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("recursively signing: %w", err)
		}
	}

	return nil
}

func signDigest(ctx context.Context, digest name.Digest, annotations map[string]interface{}, dd mutate.DupeDetector, cs Cosigner, se oci.SignedEntity, opts []ociremote.Option) error {
	payload, err := (&sigPayload.Cosign{
		Image:       digest,
		Annotations: annotations,
	}).MarshalJSON()
	if err != nil {
		return fmt.Errorf("payload: %w", err)
	}

	ociSig, _, err := cs.Cosign(ctx, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	// Attach the signature to the entity.
	newSE, err := mutate.AttachSignatureToEntity(se, ociSig, mutate.WithDupeDetector(dd))
	if err != nil {
		return err
	}

	// Publish the signatures associated with this entity
	return ociremote.WriteSignatures(digest.Repository, newSE, opts...)
}
