// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Gimel Foundation gGmbH i.G.

package oauth

import (
	"context"
	"fmt"
	"time"

	"github.com/gimelfoundation/gauth-go/pkg/adapter"
	"github.com/gimelfoundation/gauth-go/pkg/poa"
	"github.com/gimelfoundation/gauth-go/pkg/token"
)

type Engine struct {
	adapter  adapter.OAuthEngineAdapter
	signingKey *token.SigningKey
	issuer   string
}

func NewEngine(oauthAdapter adapter.OAuthEngineAdapter, signingKey *token.SigningKey, issuer string) *Engine {
	return &Engine{
		adapter:    oauthAdapter,
		signingKey: signingKey,
		issuer:     issuer,
	}
}

func (e *Engine) IssueExtendedToken(ctx context.Context, cred *poa.PoACredential, audience []string, ttl time.Duration) (string, error) {
	scopeChecksum, err := poa.ComputeScopeChecksum(cred.Scope)
	if err != nil {
		return "", fmt.Errorf("gauth oauth: compute scope checksum: %w", err)
	}

	toolHash, err := poa.ComputeToolPermissionsHash(cred.Scope.CoreVerbs)
	if err != nil {
		return "", fmt.Errorf("gauth oauth: compute tool permissions hash: %w", err)
	}

	platHash, err := poa.ComputePlatformPermissionsHash(cred.Scope.PlatformPermissions)
	if err != nil {
		return "", fmt.Errorf("gauth oauth: compute platform permissions hash: %w", err)
	}

	gauthClaims := token.ClaimsFromPoA(cred, scopeChecksum, toolHash, platHash)

	builder := token.NewTokenBuilder(e.signingKey).
		SetStandardClaims(e.issuer, cred.Parties.Subject, audience, ttl).
		SetGAuthClaims(gauthClaims)

	return builder.Build()
}

func (e *Engine) IntrospectToken(ctx context.Context, tokenString string) (*adapter.TokenIntrospection, error) {
	return e.adapter.IntrospectToken(ctx, tokenString)
}

func (e *Engine) RevokeToken(ctx context.Context, tokenString string) error {
	return e.adapter.RevokeToken(ctx, tokenString)
}

func (e *Engine) GetJWKS(ctx context.Context) ([]byte, error) {
	return e.adapter.GetJWKS(ctx)
}
