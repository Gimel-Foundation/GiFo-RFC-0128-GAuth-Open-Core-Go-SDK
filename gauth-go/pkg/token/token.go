// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Gimel Foundation gGmbH i.G.

package token

import (
        "crypto"
        "crypto/ecdsa"
        "crypto/elliptic"
        "crypto/rand"
        "crypto/rsa"
        "crypto/sha256"
        "crypto/sha512"
        "encoding/base64"
        "encoding/json"
        "errors"
        "fmt"
        "math/big"
        "strings"
        "time"

        "github.com/gimelfoundation/gauth-go/pkg/poa"
)

const MaxTokenSize = 4096

var (
        ErrHS256Prohibited    = errors.New("gauth: HS256 is prohibited (incompatible with multi-service trust)")
        ErrMissingKID         = errors.New("gauth: kid is required in JWT header")
        ErrTokenTooLarge      = errors.New("gauth: encoded token exceeds 4 KB size budget")
        ErrInvalidSignature   = errors.New("gauth: invalid token signature")
        ErrTokenExpired       = errors.New("gauth: token has expired")
        ErrTokenNotYetValid   = errors.New("gauth: token is not yet valid")
        ErrUnsupportedAlg     = errors.New("gauth: unsupported signing algorithm (only RS256 and ES256 are permitted)")
        ErrMissingGAuthClaims = errors.New("gauth: missing gauth claims namespace")
)

type Algorithm string

const (
        AlgRS256 Algorithm = "RS256"
        AlgES256 Algorithm = "ES256"
)

type Header struct {
        Algorithm Algorithm `json:"alg"`
        Type      string    `json:"typ"`
        KeyID     string    `json:"kid"`
}

type SigningKey struct {
        Algorithm  Algorithm
        KeyID      string
        PrivateKey crypto.PrivateKey
}

type VerificationKey struct {
        Algorithm Algorithm
        KeyID     string
        PublicKey crypto.PublicKey
}

type TokenBuilder struct {
        claims *ExtendedTokenClaims
        key    *SigningKey
}

func NewTokenBuilder(key *SigningKey) *TokenBuilder {
        return &TokenBuilder{
                claims: &ExtendedTokenClaims{},
                key:    key,
        }
}

func (b *TokenBuilder) SetStandardClaims(issuer, subject string, audience []string, ttl time.Duration) *TokenBuilder {
        now := time.Now().Unix()
        b.claims.Issuer = issuer
        b.claims.Subject = subject
        b.claims.Audience = audience
        b.claims.IssuedAt = now
        b.claims.NotBefore = now
        b.claims.ExpiresAt = now + int64(ttl.Seconds())
        b.claims.JWTID = fmt.Sprintf("tok_%s", generateID())
        return b
}

func (b *TokenBuilder) SetGAuthClaims(claims *GAuthClaims) *TokenBuilder {
        b.claims.GAuth = claims
        return b
}

func (b *TokenBuilder) SetMandateClaims(claims *MandateClaims) *TokenBuilder {
        b.claims.GAuthMandate = claims
        return b
}

func (b *TokenBuilder) Build() (string, error) {
        if b.key.Algorithm != AlgRS256 && b.key.Algorithm != AlgES256 {
                return "", ErrUnsupportedAlg
        }
        if b.key.KeyID == "" {
                return "", ErrMissingKID
        }

        header := Header{
                Algorithm: b.key.Algorithm,
                Type:      "JWT",
                KeyID:     b.key.KeyID,
        }

        headerJSON, err := json.Marshal(header)
        if err != nil {
                return "", fmt.Errorf("gauth: marshal header: %w", err)
        }

        claimsJSON, err := json.Marshal(b.claims)
        if err != nil {
                return "", fmt.Errorf("gauth: marshal claims: %w", err)
        }

        headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
        claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
        signingInput := headerB64 + "." + claimsB64

        sig, err := sign([]byte(signingInput), b.key)
        if err != nil {
                return "", fmt.Errorf("gauth: sign token: %w", err)
        }

        sigB64 := base64.RawURLEncoding.EncodeToString(sig)
        token := signingInput + "." + sigB64

        if len(token) > MaxTokenSize {
                return "", ErrTokenTooLarge
        }

        return token, nil
}

func Parse(tokenString string, keys []VerificationKey) (*ExtendedTokenClaims, error) {
        parts := strings.SplitN(tokenString, ".", 3)
        if len(parts) != 3 {
                return nil, errors.New("gauth: invalid token format")
        }

        headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
        if err != nil {
                return nil, fmt.Errorf("gauth: decode header: %w", err)
        }

        var header Header
        if err := json.Unmarshal(headerJSON, &header); err != nil {
                return nil, fmt.Errorf("gauth: parse header: %w", err)
        }

        if header.Algorithm != AlgRS256 && header.Algorithm != AlgES256 {
                if strings.EqualFold(string(header.Algorithm), "HS256") {
                        return nil, ErrHS256Prohibited
                }
                return nil, ErrUnsupportedAlg
        }

        if header.KeyID == "" {
                return nil, ErrMissingKID
        }

        var verifyKey *VerificationKey
        for i := range keys {
                if keys[i].KeyID == header.KeyID {
                        verifyKey = &keys[i]
                        break
                }
        }
        if verifyKey == nil {
                return nil, fmt.Errorf("gauth: no verification key found for kid %q", header.KeyID)
        }

        if verifyKey.Algorithm != header.Algorithm {
                return nil, fmt.Errorf("gauth: header alg %q does not match verification key alg %q", header.Algorithm, verifyKey.Algorithm)
        }

        signingInput := parts[0] + "." + parts[1]
        signature, err := base64.RawURLEncoding.DecodeString(parts[2])
        if err != nil {
                return nil, fmt.Errorf("gauth: decode signature: %w", err)
        }

        if err := verify([]byte(signingInput), signature, verifyKey); err != nil {
                return nil, ErrInvalidSignature
        }

        claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
        if err != nil {
                return nil, fmt.Errorf("gauth: decode claims: %w", err)
        }

        var claims ExtendedTokenClaims
        if err := json.Unmarshal(claimsJSON, &claims); err != nil {
                return nil, fmt.Errorf("gauth: parse claims: %w", err)
        }

        return &claims, nil
}

var (
        ErrScopeChecksumMismatch      = errors.New("gauth: scope checksum mismatch — token scope may have been tampered with")
        ErrToolPermHashMismatch       = errors.New("gauth: tool_permissions_hash mismatch")
        ErrPlatformPermHashMismatch   = errors.New("gauth: platform_permissions_hash mismatch")
)

func Validate(claims *ExtendedTokenClaims, audience string) error {
        now := time.Now().Unix()

        if claims.ExpiresAt != 0 && now > claims.ExpiresAt {
                return ErrTokenExpired
        }

        if claims.NotBefore != 0 && now < claims.NotBefore {
                return ErrTokenNotYetValid
        }

        if audience != "" {
                found := false
                for _, aud := range claims.Audience {
                        if aud == audience {
                                found = true
                                break
                        }
                }
                if !found {
                        return fmt.Errorf("gauth: audience %q not found in token", audience)
                }
        }

        if claims.GAuth == nil {
                return ErrMissingGAuthClaims
        }

        return nil
}

func ValidateIntegrity(claims *ExtendedTokenClaims, scope poa.Scope) error {
        if claims.GAuth == nil {
                return ErrMissingGAuthClaims
        }

        if claims.GAuth.ScopeChecksum != "" {
                computed, err := poa.ComputeScopeChecksum(scope)
                if err != nil {
                        return fmt.Errorf("gauth: compute scope checksum: %w", err)
                }
                if computed != claims.GAuth.ScopeChecksum {
                        return ErrScopeChecksumMismatch
                }
        }

        if claims.GAuth.ToolPermissionsHash != "" {
                computed, err := poa.ComputeToolPermissionsHash(scope.CoreVerbs)
                if err != nil {
                        return fmt.Errorf("gauth: compute tool permissions hash: %w", err)
                }
                if computed != claims.GAuth.ToolPermissionsHash {
                        return ErrToolPermHashMismatch
                }
        }

        if claims.GAuth.PlatformPermHash != "" {
                computed, err := poa.ComputePlatformPermissionsHash(scope.PlatformPermissions)
                if err != nil {
                        return fmt.Errorf("gauth: compute platform permissions hash: %w", err)
                }
                if computed != claims.GAuth.PlatformPermHash {
                        return ErrPlatformPermHashMismatch
                }
        }

        return nil
}

func ValidateAll(claims *ExtendedTokenClaims, audience string, scope poa.Scope) error {
        if err := Validate(claims, audience); err != nil {
                return err
        }
        return ValidateIntegrity(claims, scope)
}

func sign(data []byte, key *SigningKey) ([]byte, error) {
        switch key.Algorithm {
        case AlgRS256:
                rsaKey, ok := key.PrivateKey.(*rsa.PrivateKey)
                if !ok {
                        return nil, errors.New("gauth: RS256 requires *rsa.PrivateKey")
                }
                h := sha256.Sum256(data)
                return rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, h[:])

        case AlgES256:
                ecKey, ok := key.PrivateKey.(*ecdsa.PrivateKey)
                if !ok {
                        return nil, errors.New("gauth: ES256 requires *ecdsa.PrivateKey")
                }
                h := sha256.Sum256(data)
                r, s, err := ecdsa.Sign(rand.Reader, ecKey, h[:])
                if err != nil {
                        return nil, err
                }
                curveBits := ecKey.Curve.Params().BitSize
                keyBytes := curveBits / 8
                if curveBits%8 > 0 {
                        keyBytes++
                }
                rBytes := r.Bytes()
                sBytes := s.Bytes()
                sig := make([]byte, 2*keyBytes)
                copy(sig[keyBytes-len(rBytes):keyBytes], rBytes)
                copy(sig[2*keyBytes-len(sBytes):], sBytes)
                return sig, nil

        default:
                return nil, ErrUnsupportedAlg
        }
}

func verify(data, sig []byte, key *VerificationKey) error {
        switch key.Algorithm {
        case AlgRS256:
                rsaKey, ok := key.PublicKey.(*rsa.PublicKey)
                if !ok {
                        return errors.New("gauth: RS256 requires *rsa.PublicKey")
                }
                h := sha256.Sum256(data)
                return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, h[:], sig)

        case AlgES256:
                ecKey, ok := key.PublicKey.(*ecdsa.PublicKey)
                if !ok {
                        return errors.New("gauth: ES256 requires *ecdsa.PublicKey")
                }
                curveBits := ecKey.Curve.Params().BitSize
                keyBytes := curveBits / 8
                if curveBits%8 > 0 {
                        keyBytes++
                }
                if len(sig) != 2*keyBytes {
                        return ErrInvalidSignature
                }
                r := new(big.Int).SetBytes(sig[:keyBytes])
                s := new(big.Int).SetBytes(sig[keyBytes:])
                h := sha256.Sum256(data)
                if !ecdsa.Verify(ecKey, h[:], r, s) {
                        return ErrInvalidSignature
                }
                return nil

        default:
                return ErrUnsupportedAlg
        }
}

func generateID() string {
        b := make([]byte, 16)
        _, _ = rand.Read(b)
        h := sha512.Sum512_256(b)
        return fmt.Sprintf("%x", h[:16])
}

func GenerateRS256Key(keyID string) (*SigningKey, *VerificationKey, error) {
        privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
                return nil, nil, err
        }
        return &SigningKey{
                        Algorithm:  AlgRS256,
                        KeyID:      keyID,
                        PrivateKey: privateKey,
                }, &VerificationKey{
                        Algorithm: AlgRS256,
                        KeyID:     keyID,
                        PublicKey: &privateKey.PublicKey,
                }, nil
}

func GenerateES256Key(keyID string) (*SigningKey, *VerificationKey, error) {
        privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
        if err != nil {
                return nil, nil, err
        }
        return &SigningKey{
                        Algorithm:  AlgES256,
                        KeyID:      keyID,
                        PrivateKey: privateKey,
                }, &VerificationKey{
                        Algorithm: AlgES256,
                        KeyID:     keyID,
                        PublicKey: &privateKey.PublicKey,
                }, nil
}
