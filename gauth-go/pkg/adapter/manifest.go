package adapter

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	ErrManifestParse          = errors.New("gauth: manifest parse error")
	ErrManifestVersion        = errors.New("gauth: manifest_version must be \"1.0\"")
	ErrManifestType           = errors.New("gauth: adapter_type must be \"C\"")
	ErrManifestSlotMismatch   = errors.New("gauth: manifest slot_name does not match target slot")
	ErrManifestNamespace      = errors.New("gauth: namespace must start with \"@gimel/\"")
	ErrManifestNamespaceSlot  = errors.New("gauth: namespace does not match canonical slot namespace")
	ErrManifestIssuer         = errors.New("gauth: issuer must be \"gimel-foundation\"")
	ErrManifestExpired        = errors.New("gauth: manifest has expired")
	ErrManifestNotYetValid    = errors.New("gauth: manifest issued_at is in the future")
	ErrManifestMaxValidity    = errors.New("gauth: manifest validity exceeds 1 year")
	ErrManifestSignature      = errors.New("gauth: manifest Ed25519 signature verification failed")
	ErrManifestUntrustedKey   = errors.New("gauth: manifest public_key not in trusted key set")
	ErrManifestRevokedKey     = errors.New("gauth: manifest public_key has been revoked")
	ErrManifestRevokedVersion = errors.New("gauth: adapter_version has been revoked")
)

const maxManifestValidityDays = 365

type ManifestVerifier struct {
	trustedKeys     map[string]ed25519.PublicKey
	revokedKeys     map[string]bool
	revokedVersions map[string]bool
	nowFunc         func() time.Time
}

func NewManifestVerifier() *ManifestVerifier {
	return &ManifestVerifier{
		trustedKeys:     make(map[string]ed25519.PublicKey),
		revokedKeys:     make(map[string]bool),
		revokedVersions: make(map[string]bool),
		nowFunc:         time.Now,
	}
}

func (v *ManifestVerifier) AddTrustedKey(keyID string, pubKey ed25519.PublicKey) {
	v.trustedKeys[keyID] = pubKey
}

func (v *ManifestVerifier) RevokeKey(pubKeyHex string) {
	v.revokedKeys[pubKeyHex] = true
}

func (v *ManifestVerifier) RevokeVersion(version string) {
	v.revokedVersions[version] = true
}

func (v *ManifestVerifier) SetNowFunc(f func() time.Time) {
	v.nowFunc = f
}

func (v *ManifestVerifier) Verify(manifestJSON []byte, targetSlot SlotName) (*SealedManifest, error) {
	var m SealedManifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifestParse, err)
	}

	if m.ManifestVersion != "1.0" {
		return nil, ErrManifestVersion
	}
	if m.AdapterType != "C" {
		return nil, ErrManifestType
	}
	if SlotName(m.SlotName) != targetSlot {
		return nil, ErrManifestSlotMismatch
	}
	if !strings.HasPrefix(m.Namespace, "@gimel/") {
		return nil, ErrManifestNamespace
	}
	if canonical, ok := CanonicalSlotNamespace[targetSlot]; ok {
		if m.Namespace != canonical {
			return nil, ErrManifestNamespaceSlot
		}
	}
	if m.Issuer != "gimel-foundation" {
		return nil, ErrManifestIssuer
	}

	now := v.nowFunc()
	issuedAt, err := time.Parse(time.RFC3339, m.IssuedAt)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid issued_at: %v", ErrManifestParse, err)
	}
	expiresAt, err := time.Parse(time.RFC3339, m.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid expires_at: %v", ErrManifestParse, err)
	}

	if issuedAt.After(now) {
		return nil, ErrManifestNotYetValid
	}
	if expiresAt.Before(now) || expiresAt.Equal(now) {
		return nil, ErrManifestExpired
	}
	if expiresAt.Sub(issuedAt) > time.Duration(maxManifestValidityDays)*24*time.Hour {
		return nil, ErrManifestMaxValidity
	}

	pubKeyBytes, err := hex.DecodeString(m.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid public_key hex: %v", ErrManifestParse, err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public_key must be %d bytes", ErrManifestParse, ed25519.PublicKeySize)
	}

	sigBytes, err := hex.DecodeString(m.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid signature hex: %v", ErrManifestParse, err)
	}

	if v.revokedKeys[m.PublicKey] {
		return nil, ErrManifestRevokedKey
	}
	if v.revokedVersions[m.AdapterVersion] {
		return nil, ErrManifestRevokedVersion
	}

	trusted := false
	for _, tk := range v.trustedKeys {
		if hex.EncodeToString(tk) == m.PublicKey {
			trusted = true
			break
		}
	}
	if !trusted {
		return nil, ErrManifestUntrustedKey
	}

	canonical, err := canonicalizeManifest(manifestJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalization failed: %v", ErrManifestParse, err)
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)
	if !ed25519.Verify(pubKey, canonical, sigBytes) {
		return nil, ErrManifestSignature
	}

	return &m, nil
}

func canonicalizeManifest(manifestJSON []byte) ([]byte, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(manifestJSON, &raw); err != nil {
		return nil, err
	}

	delete(raw, "signature")

	return canonicalizeJSON(raw)
}

func canonicalizeJSON(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var buf []byte
		buf = append(buf, '{')
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			keyBytes, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			buf = append(buf, keyBytes...)
			buf = append(buf, ':')
			valBytes, err := canonicalizeJSON(val[k])
			if err != nil {
				return nil, err
			}
			buf = append(buf, valBytes...)
		}
		buf = append(buf, '}')
		return buf, nil

	case []interface{}:
		var buf []byte
		buf = append(buf, '[')
		for i, item := range val {
			if i > 0 {
				buf = append(buf, ',')
			}
			itemBytes, err := canonicalizeJSON(item)
			if err != nil {
				return nil, err
			}
			buf = append(buf, itemBytes...)
		}
		buf = append(buf, ']')
		return buf, nil

	default:
		return json.Marshal(v)
	}
}
