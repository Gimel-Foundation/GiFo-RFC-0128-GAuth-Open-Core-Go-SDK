// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Gimel Foundation gGmbH i.G.

package pep

import (
	"encoding/json"
	"net/http"
	"time"
)

type HTTPHandler struct {
	PEP *PEP
}

func NewHTTPHandler(p *PEP) *HTTPHandler {
	return &HTTPHandler{PEP: p}
}

func (h *HTTPHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/gauth/pep/v1/enforce", h.handleEnforce)
	mux.HandleFunc("/gauth/pep/v1/enforce/batch", h.handleBatchEnforce)
	mux.HandleFunc("/gauth/pep/v1/policy", h.handlePolicy)
	mux.HandleFunc("/gauth/pep/v1/health", h.handleHealth)
}

func (h *HTTPHandler) handleEnforce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "INVALID_REQUEST", "Method not allowed")
		return
	}

	var req EnforcementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body: "+err.Error())
		return
	}

	if reqID := r.Header.Get("X-Request-ID"); reqID != "" && req.RequestID == "" {
		req.RequestID = reqID
	}

	decision, err := h.PEP.EnforceAction(&req)
	if err != nil {
		if enfErr, ok := err.(*EnforcementError); ok {
			status := errorCodeToHTTPStatus(enfErr.ErrorCode)
			h.writeJSON(w, status, enfErr)
			return
		}
		h.writeError(w, http.StatusInternalServerError, "PEP_INTERNAL_ERROR", err.Error())
		return
	}

	w.Header().Set("X-PEP-Version", h.PEP.Version)
	w.Header().Set("X-PEP-Interface-Version", InterfaceVersion)
	h.writeJSON(w, http.StatusOK, decision)
}

func (h *HTTPHandler) handleBatchEnforce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "INVALID_REQUEST", "Method not allowed")
		return
	}

	var body struct {
		Requests []EnforcementRequest `json:"requests"`
		Mode     BatchMode            `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body: "+err.Error())
		return
	}

	decision, err := h.PEP.BatchEnforce(body.Requests, body.Mode)
	if err != nil {
		if enfErr, ok := err.(*EnforcementError); ok {
			status := errorCodeToHTTPStatus(enfErr.ErrorCode)
			h.writeJSON(w, status, enfErr)
			return
		}
		h.writeError(w, http.StatusInternalServerError, "PEP_INTERNAL_ERROR", err.Error())
		return
	}

	w.Header().Set("X-PEP-Version", h.PEP.Version)
	w.Header().Set("X-PEP-Interface-Version", InterfaceVersion)
	h.writeJSON(w, http.StatusOK, decision)
}

func (h *HTTPHandler) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "INVALID_REQUEST", "Method not allowed")
		return
	}

	var body struct {
		Credential CredentialReference `json:"credential"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body: "+err.Error())
		return
	}

	if body.Credential.PoASnapshot == nil {
		h.writeError(w, http.StatusBadRequest, "CREDENTIAL_PARSE_ERROR", "poa_snapshot is required")
		return
	}

	policy := h.PEP.GetEnforcementPolicy(body.Credential.PoASnapshot)
	h.writeJSON(w, http.StatusOK, policy)
}

func (h *HTTPHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "INVALID_REQUEST", "Method not allowed")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{
		"status":            "ok",
		"pep_version":       h.PEP.Version,
		"interface_version": InterfaceVersion,
	})
}

func (h *HTTPHandler) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (h *HTTPHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, &EnforcementError{
		ErrorCode: code,
		Message:   message,
		Timestamp: time.Now(),
	})
}

func errorCodeToHTTPStatus(code string) int {
	switch code {
	case "INVALID_REQUEST", "CREDENTIAL_PARSE_ERROR":
		return http.StatusBadRequest
	case "ISSUER_UNREACHABLE":
		return http.StatusBadGateway
	case "EVALUATION_TIMEOUT":
		return http.StatusGatewayTimeout
	default:
		return http.StatusInternalServerError
	}
}
