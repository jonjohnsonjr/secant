// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rekor

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/jonjohnsonjr/secant/rekord"
	"github.com/jonjohnsonjr/secant/tlog"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"

	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type Cosigner interface {
	Cosign(context.Context, io.Reader) (oci.Signature, crypto.PublicKey, error)
}

// signerWrapper calls a wrapped, inner signer then uploads either the Cert or Pub(licKey) of the results to Rekor, then adds the resulting `Bundle`
type signerWrapper struct {
	inner Cosigner

	rClient *client.Rekor
}

var _ Cosigner = (*signerWrapper)(nil)

// Cosign implements Cosigner.
func (rs *signerWrapper) Cosign(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	sig, pub, err := rs.inner.Cosign(ctx, payload)
	if err != nil {
		return nil, nil, err
	}

	payloadBytes, err := sig.Payload()
	if err != nil {
		return nil, nil, err
	}
	b64Sig, err := sig.Base64Signature()
	if err != nil {
		return nil, nil, err
	}
	sigBytes, err := base64.StdEncoding.DecodeString(b64Sig)
	if err != nil {
		return nil, nil, err
	}

	// Upload the cert or the public key, depending on what we have
	cert, err := sig.Cert()
	if err != nil {
		return nil, nil, err
	}

	var rekorBytes []byte
	if cert != nil {
		rekorBytes, err = cryptoutils.MarshalCertificateToPEM(cert)
	} else {
		rekorBytes, err = cryptoutils.MarshalPublicKeyToPEM(pub)
	}
	if err != nil {
		return nil, nil, err
	}

	checkSum := sha256.New()
	if _, err := checkSum.Write(payloadBytes); err != nil {
		return nil, nil, err
	}

	pe := rekord.Entry(checkSum, sigBytes, rekorBytes)

	entry, err := tlog.Upload(ctx, rs.rClient, pe)
	if err != nil {
		return nil, nil, err
	}

	fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)
	bundle, err := cbundle.EntryToBundle(entry), nil
	if err != nil {
		return nil, nil, err
	}

	newSig, err := mutate.Signature(sig, mutate.WithBundle(bundle))
	if err != nil {
		return nil, nil, err
	}

	return newSig, pub, nil
}

// NewCosigner returns a Cosigner which uploads the signature to Rekor
func NewCosigner(inner Cosigner, rClient *client.Rekor) Cosigner {
	return &signerWrapper{
		inner:   inner,
		rClient: rClient,
	}
}
