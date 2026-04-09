package management

import (
        "encoding/json"
        "net/http"
        "strconv"
        "time"

        "github.com/gimelfoundation/gauth-go/pkg/poa"
)

type HTTPHandler struct {
        Manager *MandateManager
}

func NewHTTPHandler(mgr *MandateManager) *HTTPHandler {
        return &HTTPHandler{Manager: mgr}
}

func (h *HTTPHandler) RegisterRoutes(mux *http.ServeMux) {
        mux.HandleFunc("/gauth/mgmt/v1/mandates", h.handleMandates)
        mux.HandleFunc("/gauth/mgmt/v1/mandates/", h.handleMandateByID)
}

func (h *HTTPHandler) handleMandates(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case http.MethodPost:
                h.createMandate(w, r)
        case http.MethodGet:
                h.listMandates(w, r)
        default:
                writeErrorResponse(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
        }
}

func (h *HTTPHandler) handleMandateByID(w http.ResponseWriter, r *http.Request) {
        id := r.URL.Path[len("/gauth/mgmt/v1/mandates/"):]

        parts := splitPath(id)
        if len(parts) == 0 {
                writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "Mandate ID is required")
                return
        }
        mandateID := parts[0]

        if len(parts) > 1 {
                action := parts[1]
                switch action {
                case "activate":
                        h.activateMandate(w, r, mandateID)
                case "suspend":
                        h.suspendMandate(w, r, mandateID)
                case "resume":
                        h.resumeMandate(w, r, mandateID)
                case "revoke":
                        h.revokeMandate(w, r, mandateID)
                case "extend-ttl":
                        h.extendTTL(w, r, mandateID)
                case "increase-budget":
                        h.increaseBudget(w, r, mandateID)
                case "delegate":
                        h.createDelegation(w, r, mandateID)
                case "revoke-delegation":
                        h.revokeDelegation(w, r, mandateID)
                case "governance-profile":
                        h.assignGovernanceProfile(w, r, mandateID)
                default:
                        writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "Unknown action")
                }
                return
        }

        if r.Method == http.MethodGet {
                h.getMandate(w, r, mandateID)
                return
        }

        writeErrorResponse(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
}

func (h *HTTPHandler) createMandate(w http.ResponseWriter, r *http.Request) {
        var req MandateCreationRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
                return
        }

        actorID := r.Header.Get("X-Actor-ID")
        if actorID == "" {
                actorID = "unknown"
        }

        resp, err := h.Manager.CreateMandate(&req, actorID)
        if err != nil {
                writeErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
                return
        }

        writeJSONResponse(w, http.StatusCreated, resp)
}

func (h *HTTPHandler) getMandate(w http.ResponseWriter, _ *http.Request, id string) {
        mandate, err := h.Manager.GetMandate(id)
        if err != nil {
                writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", err.Error())
                return
        }
        writeJSONResponse(w, http.StatusOK, mandate)
}

func (h *HTTPHandler) listMandates(w http.ResponseWriter, r *http.Request) {
        q := r.URL.Query()
        customerID := q.Get("customer_id")
        projectID := q.Get("project_id")

        var status *poa.MandateStatus
        if s := q.Get("status"); s != "" {
                ms := poa.MandateStatus(s)
                status = &ms
        }

        limit := 50
        if l := q.Get("limit"); l != "" {
                if v, err := strconv.Atoi(l); err == nil {
                        limit = v
                }
        }

        offset := 0
        if o := q.Get("offset"); o != "" {
                if v, err := strconv.Atoi(o); err == nil {
                        offset = v
                }
        }

        mandates, err := h.Manager.ListMandates(customerID, projectID, status, limit, offset)
        if err != nil {
                writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
                return
        }

        writeJSONResponse(w, http.StatusOK, map[string]interface{}{
                "mandates": mandates,
                "total":    len(mandates),
        })
}

func (h *HTTPHandler) activateMandate(w http.ResponseWriter, r *http.Request, id string) {
        if r.Method != http.MethodPost {
                writeErrorResponse(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
                return
        }
        actorID := r.Header.Get("X-Actor-ID")
        if err := h.Manager.ActivateMandate(id, actorID); err != nil {
                writeErrorResponse(w, http.StatusBadRequest, "TRANSITION_ERROR", err.Error())
                return
        }
        mandate, _ := h.Manager.GetMandate(id)
        writeJSONResponse(w, http.StatusOK, mandate)
}

func (h *HTTPHandler) suspendMandate(w http.ResponseWriter, r *http.Request, id string) {
        if r.Method != http.MethodPost {
                writeErrorResponse(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
                return
        }
        var body struct {
                Reason string `json:"reason"`
        }
        json.NewDecoder(r.Body).Decode(&body)
        actorID := r.Header.Get("X-Actor-ID")
        if err := h.Manager.SuspendMandate(id, actorID, body.Reason); err != nil {
                writeErrorResponse(w, http.StatusBadRequest, "TRANSITION_ERROR", err.Error())
                return
        }
        mandate, _ := h.Manager.GetMandate(id)
        writeJSONResponse(w, http.StatusOK, mandate)
}

func (h *HTTPHandler) resumeMandate(w http.ResponseWriter, r *http.Request, id string) {
        if r.Method != http.MethodPost {
                writeErrorResponse(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
                return
        }
        actorID := r.Header.Get("X-Actor-ID")
        if err := h.Manager.ResumeMandate(id, actorID); err != nil {
                writeErrorResponse(w, http.StatusBadRequest, "TRANSITION_ERROR", err.Error())
                return
        }
        mandate, _ := h.Manager.GetMandate(id)
        writeJSONResponse(w, http.StatusOK, mandate)
}

func (h *HTTPHandler) revokeMandate(w http.ResponseWriter, r *http.Request, id string) {
        if r.Method != http.MethodPost {
                writeErrorResponse(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
                return
        }
        var body struct {
                Reason string `json:"reason"`
        }
        json.NewDecoder(r.Body).Decode(&body)
        actorID := r.Header.Get("X-Actor-ID")
        if err := h.Manager.RevokeMandate(id, actorID, body.Reason); err != nil {
                writeErrorResponse(w, http.StatusBadRequest, "TRANSITION_ERROR", err.Error())
                return
        }
        mandate, _ := h.Manager.GetMandate(id)
        writeJSONResponse(w, http.StatusOK, mandate)
}

func (h *HTTPHandler) extendTTL(w http.ResponseWriter, r *http.Request, id string) {
        if r.Method != http.MethodPost {
                writeErrorResponse(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
                return
        }
        var body struct {
                AdditionalSeconds int `json:"additional_seconds"`
        }
        if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
                writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
                return
        }
        actorID := r.Header.Get("X-Actor-ID")
        if err := h.Manager.ExtendTTL(id, actorID, body.AdditionalSeconds); err != nil {
                writeErrorResponse(w, http.StatusBadRequest, "OPERATION_ERROR", err.Error())
                return
        }
        mandate, _ := h.Manager.GetMandate(id)
        writeJSONResponse(w, http.StatusOK, mandate)
}

func (h *HTTPHandler) increaseBudget(w http.ResponseWriter, r *http.Request, id string) {
        if r.Method != http.MethodPost {
                writeErrorResponse(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
                return
        }
        var body struct {
                AdditionalCents int `json:"additional_cents"`
        }
        if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
                writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
                return
        }
        actorID := r.Header.Get("X-Actor-ID")
        if err := h.Manager.IncreaseBudget(id, actorID, body.AdditionalCents); err != nil {
                writeErrorResponse(w, http.StatusBadRequest, "OPERATION_ERROR", err.Error())
                return
        }
        mandate, _ := h.Manager.GetMandate(id)
        writeJSONResponse(w, http.StatusOK, mandate)
}

func (h *HTTPHandler) createDelegation(w http.ResponseWriter, r *http.Request, id string) {
        if r.Method != http.MethodPost {
                writeErrorResponse(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
                return
        }
        var body struct {
                DelegateeID string `json:"delegatee_id"`
        }
        if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
                writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
                return
        }
        if body.DelegateeID == "" {
                writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "delegatee_id is required")
                return
        }
        actorID := r.Header.Get("X-Actor-ID")
        if err := h.Manager.CreateDelegation(id, actorID, body.DelegateeID); err != nil {
                writeErrorResponse(w, http.StatusBadRequest, "OPERATION_ERROR", err.Error())
                return
        }
        mandate, _ := h.Manager.GetMandate(id)
        writeJSONResponse(w, http.StatusOK, mandate)
}

func (h *HTTPHandler) revokeDelegation(w http.ResponseWriter, r *http.Request, id string) {
        if r.Method != http.MethodPost {
                writeErrorResponse(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
                return
        }
        var body struct {
                DelegateeID string `json:"delegatee_id"`
        }
        if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
                writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
                return
        }
        actorID := r.Header.Get("X-Actor-ID")
        if err := h.Manager.RevokeDelegation(id, actorID, body.DelegateeID); err != nil {
                writeErrorResponse(w, http.StatusBadRequest, "OPERATION_ERROR", err.Error())
                return
        }
        mandate, _ := h.Manager.GetMandate(id)
        writeJSONResponse(w, http.StatusOK, mandate)
}

func (h *HTTPHandler) assignGovernanceProfile(w http.ResponseWriter, r *http.Request, id string) {
        if r.Method != http.MethodPost {
                writeErrorResponse(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
                return
        }
        var body struct {
                Profile poa.GovernanceProfile `json:"profile"`
        }
        if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
                writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
                return
        }
        actorID := r.Header.Get("X-Actor-ID")
        if err := h.Manager.AssignGovernanceProfile(id, actorID, body.Profile); err != nil {
                writeErrorResponse(w, http.StatusBadRequest, "OPERATION_ERROR", err.Error())
                return
        }
        mandate, _ := h.Manager.GetMandate(id)
        writeJSONResponse(w, http.StatusOK, mandate)
}

func writeJSONResponse(w http.ResponseWriter, status int, v interface{}) {
        w.Header().Set("Content-Type", "application/json; charset=utf-8")
        w.WriteHeader(status)
        json.NewEncoder(w).Encode(v)
}

type errorResponse struct {
        ErrorCode string    `json:"error_code"`
        Message   string    `json:"message"`
        Timestamp time.Time `json:"timestamp"`
}

func writeErrorResponse(w http.ResponseWriter, status int, code, message string) {
        writeJSONResponse(w, status, errorResponse{
                ErrorCode: code,
                Message:   message,
                Timestamp: time.Now(),
        })
}

func splitPath(path string) []string {
        var parts []string
        current := ""
        for _, c := range path {
                if c == '/' {
                        if current != "" {
                                parts = append(parts, current)
                        }
                        current = ""
                } else {
                        current += string(c)
                }
        }
        if current != "" {
                parts = append(parts, current)
        }
        return parts
}
