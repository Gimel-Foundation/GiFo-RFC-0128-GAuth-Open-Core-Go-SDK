package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
)

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use,omitempty"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg,omitempty"`

	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	Curve string `json:"crv,omitempty"`
	X     string `json:"x,omitempty"`
	Y     string `json:"y,omitempty"`
}

func FetchJWKS(url string) (*JWKSet, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("gauth: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gauth: JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks JWKSet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("gauth: decode JWKS: %w", err)
	}

	return &jwks, nil
}

func (j *JWKSet) ToVerificationKeys() ([]VerificationKey, error) {
	var keys []VerificationKey
	for _, jwk := range j.Keys {
		vk, err := jwk.ToVerificationKey()
		if err != nil {
			continue
		}
		keys = append(keys, *vk)
	}
	return keys, nil
}

func (j *JWK) ToVerificationKey() (*VerificationKey, error) {
	switch j.KeyType {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
		if err != nil {
			return nil, fmt.Errorf("gauth: decode RSA N: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
		if err != nil {
			return nil, fmt.Errorf("gauth: decode RSA E: %w", err)
		}
		n := new(big.Int).SetBytes(nBytes)
		e := int(new(big.Int).SetBytes(eBytes).Int64())
		return &VerificationKey{
			Algorithm: AlgRS256,
			KeyID:     j.KeyID,
			PublicKey: &rsa.PublicKey{N: n, E: e},
		}, nil

	case "EC":
		if j.Curve != "P-256" {
			return nil, fmt.Errorf("gauth: unsupported EC curve %q", j.Curve)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return nil, fmt.Errorf("gauth: decode EC X: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(j.Y)
		if err != nil {
			return nil, fmt.Errorf("gauth: decode EC Y: %w", err)
		}
		return &VerificationKey{
			Algorithm: AlgES256,
			KeyID:     j.KeyID,
			PublicKey: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(xBytes),
				Y:     new(big.Int).SetBytes(yBytes),
			},
		}, nil

	default:
		return nil, fmt.Errorf("gauth: unsupported key type %q", j.KeyType)
	}
}
