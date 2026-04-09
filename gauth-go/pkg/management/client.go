package management

import (
        "bytes"
        "encoding/json"
        "fmt"
        "io"
        "net/http"
        "time"

        "github.com/gimelfoundation/gauth-go/pkg/poa"
)

type APIError struct {
        ErrorCode string    `json:"error_code"`
        Message   string    `json:"message"`
        Timestamp time.Time `json:"timestamp"`
        HTTPCode  int       `json:"-"`
}

func (e *APIError) Error() string {
        return fmt.Sprintf("gauth: API error %s (HTTP %d): %s", e.ErrorCode, e.HTTPCode, e.Message)
}

type ClientConfig struct {
        BaseURL    string
        HTTPClient *http.Client
        ActorID    string
}

type Client struct {
        baseURL    string
        httpClient *http.Client
        actorID    string
}

func NewClient(cfg ClientConfig) *Client {
        c := &Client{
                baseURL: cfg.BaseURL,
                actorID: cfg.ActorID,
        }
        if cfg.HTTPClient != nil {
                c.httpClient = cfg.HTTPClient
        } else {
                c.httpClient = &http.Client{Timeout: 30 * time.Second}
        }
        if c.baseURL == "" {
                c.baseURL = "http://localhost:8080"
        }
        return c
}

func (c *Client) CreateMandate(req *MandateCreationRequest) (*MandateCreationResponse, error) {
        var resp MandateCreationResponse
        if err := c.doJSON(http.MethodPost, "/gauth/mgmt/v1/mandates", req, &resp); err != nil {
                return nil, err
        }
        return &resp, nil
}

func (c *Client) GetMandate(id string) (*Mandate, error) {
        var mandate Mandate
        if err := c.doJSON(http.MethodGet, "/gauth/mgmt/v1/mandates/"+id, nil, &mandate); err != nil {
                return nil, err
        }
        return &mandate, nil
}

type ListMandatesResponse struct {
        Mandates []Mandate `json:"mandates"`
        Total    int       `json:"total"`
}

func (c *Client) ListMandates(customerID, projectID string, status *poa.MandateStatus, limit, offset int) (*ListMandatesResponse, error) {
        path := fmt.Sprintf("/gauth/mgmt/v1/mandates?limit=%d&offset=%d", limit, offset)
        if customerID != "" {
                path += "&customer_id=" + customerID
        }
        if projectID != "" {
                path += "&project_id=" + projectID
        }
        if status != nil {
                path += "&status=" + string(*status)
        }
        var resp ListMandatesResponse
        if err := c.doJSON(http.MethodGet, path, nil, &resp); err != nil {
                return nil, err
        }
        return &resp, nil
}

func (c *Client) ActivateMandate(id string) (*Mandate, error) {
        return c.doMandateAction(id, "activate", nil)
}

func (c *Client) SuspendMandate(id, reason string) (*Mandate, error) {
        return c.doMandateAction(id, "suspend", map[string]string{"reason": reason})
}

func (c *Client) ResumeMandate(id string) (*Mandate, error) {
        return c.doMandateAction(id, "resume", nil)
}

func (c *Client) RevokeMandate(id, reason string) (*Mandate, error) {
        return c.doMandateAction(id, "revoke", map[string]string{"reason": reason})
}

func (c *Client) ExtendTTL(id string, additionalSeconds int) (*Mandate, error) {
        return c.doMandateAction(id, "extend-ttl", map[string]int{"additional_seconds": additionalSeconds})
}

func (c *Client) IncreaseBudget(id string, additionalCents int) (*Mandate, error) {
        return c.doMandateAction(id, "increase-budget", map[string]int{"additional_cents": additionalCents})
}

func (c *Client) CreateDelegation(id, delegateeID string) (*Mandate, error) {
        return c.doMandateAction(id, "delegate", map[string]string{"delegatee_id": delegateeID})
}

func (c *Client) RevokeDelegation(id, delegateeID string) (*Mandate, error) {
        return c.doMandateAction(id, "revoke-delegation", map[string]string{"delegatee_id": delegateeID})
}

func (c *Client) AssignGovernanceProfile(id string, profile poa.GovernanceProfile) (*Mandate, error) {
        return c.doMandateAction(id, "governance-profile", map[string]poa.GovernanceProfile{"profile": profile})
}

func (c *Client) doMandateAction(id, action string, body interface{}) (*Mandate, error) {
        var mandate Mandate
        if err := c.doJSON(http.MethodPost, "/gauth/mgmt/v1/mandates/"+id+"/"+action, body, &mandate); err != nil {
                return nil, err
        }
        return &mandate, nil
}

func (c *Client) doJSON(method, path string, body interface{}, result interface{}) error {
        var reqBody io.Reader
        if body != nil {
                b, err := json.Marshal(body)
                if err != nil {
                        return fmt.Errorf("gauth: marshal request: %w", err)
                }
                reqBody = bytes.NewReader(b)
        }

        req, err := http.NewRequest(method, c.baseURL+path, reqBody)
        if err != nil {
                return fmt.Errorf("gauth: create request: %w", err)
        }
        req.Header.Set("Content-Type", "application/json")
        if c.actorID != "" {
                req.Header.Set("X-Actor-ID", c.actorID)
        }

        resp, err := c.httpClient.Do(req)
        if err != nil {
                return fmt.Errorf("gauth: HTTP request failed: %w", err)
        }
        defer resp.Body.Close()

        respBody, err := io.ReadAll(resp.Body)
        if err != nil {
                return fmt.Errorf("gauth: read response: %w", err)
        }

        if resp.StatusCode >= 400 {
                var apiErr APIError
                if jsonErr := json.Unmarshal(respBody, &apiErr); jsonErr != nil {
                        return &APIError{
                                ErrorCode: "UNKNOWN",
                                Message:   string(respBody),
                                HTTPCode:  resp.StatusCode,
                        }
                }
                apiErr.HTTPCode = resp.StatusCode
                return &apiErr
        }

        if result != nil {
                if err := json.Unmarshal(respBody, result); err != nil {
                        return fmt.Errorf("gauth: decode response: %w", err)
                }
        }

        return nil
}
