package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/protectedapi"
)

const (
	defaultBaseURL      = "http://127.0.0.1:8181"
	defaultDecisionPath = "/v1/data/containgo/authz/decision"
	quarantineDataPath  = "/v1/data/containgo/quarantined"
	maxResponseBytes    = 1 << 20
)

// Config contains the OPA HTTP client configuration.
type Config struct {
	BaseURL      string
	DecisionPath string
	Timeout      time.Duration
}

// DefaultConfig returns local-development OPA settings.
func DefaultConfig() Config {
	return Config{
		BaseURL:      defaultBaseURL,
		DecisionPath: defaultDecisionPath,
		Timeout:      3 * time.Second,
	}
}

// Client evaluates authorization decisions and manages OPA quarantine data.
type Client struct {
	baseURL      string
	decisionPath string
	httpClient   *http.Client

	// The quarantine document is updated using read-modify-write.
	// This mutex prevents lost updates inside one ContainGo process.
	dataMu sync.Mutex
}

// NewClient creates an OPA REST client.
func NewClient(
	config Config,
) (*Client, error) {
	baseURL := strings.TrimRight(
		strings.TrimSpace(config.BaseURL),
		"/",
	)

	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf(
			"parse OPA base URL: %w",
			err,
		)
	}

	if parsedBaseURL.Scheme != "http" &&
		parsedBaseURL.Scheme != "https" {
		return nil, errors.New(
			"OPA base URL must use HTTP or HTTPS",
		)
	}

	if parsedBaseURL.Host == "" {
		return nil, errors.New(
			"OPA base URL must include a host",
		)
	}

	if parsedBaseURL.RawQuery != "" ||
		parsedBaseURL.Fragment != "" {
		return nil, errors.New(
			"OPA base URL must not include a query or fragment",
		)
	}

	decisionPath := strings.TrimSpace(
		config.DecisionPath,
	)

	if decisionPath == "" {
		decisionPath = defaultDecisionPath
	}

	if !strings.HasPrefix(
		decisionPath,
		"/",
	) {
		decisionPath = "/" + decisionPath
	}

	if strings.Contains(
		decisionPath,
		"?",
	) {
		return nil, errors.New(
			"OPA decision path must not include a query",
		)
	}

	if config.Timeout <= 0 {
		config.Timeout = 3 * time.Second
	}

	return &Client{
		baseURL:      baseURL,
		decisionPath: decisionPath,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}, nil
}

// Authorize asks OPA whether one workload may access an endpoint.
//
// Any communication error, malformed response, or undefined decision is
// returned as an error. The protected API then fails closed.
func (c *Client) Authorize(
	ctx context.Context,
	input protectedapi.AuthorizationInput,
) (protectedapi.AuthorizationDecision, error) {
	if err := validateContext(ctx); err != nil {
		return protectedapi.AuthorizationDecision{}, err
	}

	input.SPIFFEID = strings.TrimSpace(
		input.SPIFFEID,
	)
	input.Method = strings.ToUpper(
		strings.TrimSpace(input.Method),
	)
	input.Path = strings.TrimSpace(
		input.Path,
	)

	if input.SPIFFEID == "" {
		return protectedapi.AuthorizationDecision{}, errors.New(
			"OPA authorization SPIFFE ID must not be empty",
		)
	}

	if input.Method == "" {
		return protectedapi.AuthorizationDecision{}, errors.New(
			"OPA authorization HTTP method must not be empty",
		)
	}

	if input.Path == "" {
		return protectedapi.AuthorizationDecision{}, errors.New(
			"OPA authorization path must not be empty",
		)
	}

	requestBody := decisionRequest{
		Input: decisionInput{
			SPIFFEID: input.SPIFFEID,
			Method:   input.Method,
			Path:     input.Path,
		},
	}

	var response decisionResponse

	decisionURL, err := c.decisionURL()
	if err != nil {
		return protectedapi.AuthorizationDecision{}, err
	}

	if err = c.doJSON(
		ctx,
		http.MethodPost,
		decisionURL,
		requestBody,
		&response,
	); err != nil {
		return protectedapi.AuthorizationDecision{}, fmt.Errorf(
			"evaluate OPA authorization decision: %w",
			err,
		)
	}

	if response.Result == nil {
		return protectedapi.AuthorizationDecision{}, errors.New(
			"OPA authorization decision is undefined",
		)
	}

	reason := strings.TrimSpace(
		response.Result.Reason,
	)

	if reason == "" {
		if response.Result.Allowed {
			reason = "OPA allowed the request"
		} else {
			reason = "OPA denied the request"
		}
	}

	return protectedapi.AuthorizationDecision{
		Allowed: response.Result.Allowed,
		Reason:  reason,
	}, nil
}

// Check verifies that the OPA server is operational.
func (c *Client) Check(
	ctx context.Context,
) error {
	if err := validateContext(ctx); err != nil {
		return err
	}

	if err := c.doJSON(
		ctx,
		http.MethodGet,
		c.endpoint("/health"),
		nil,
		nil,
	); err != nil {
		return fmt.Errorf(
			"OPA health check: %w",
			err,
		)
	}

	return nil
}

// SetQuarantined adds or removes one workload from OPA's quarantine data.
func (c *Client) SetQuarantined(
	ctx context.Context,
	spiffeID string,
	quarantined bool,
) error {
	if err := validateContext(ctx); err != nil {
		return err
	}

	spiffeID = strings.TrimSpace(spiffeID)

	if !domain.IsKnownWorkloadID(spiffeID) {
		return fmt.Errorf(
			"unknown workload SPIFFE ID %q",
			spiffeID,
		)
	}

	c.dataMu.Lock()
	defer c.dataMu.Unlock()

	current, err := c.getQuarantinedUnlocked(ctx)
	if err != nil {
		return err
	}

	if quarantined {
		current[spiffeID] = true
	} else {
		delete(
			current,
			spiffeID,
		)
	}

	if err = c.putQuarantinedUnlocked(
		ctx,
		current,
	); err != nil {
		return err
	}

	return nil
}

// ReplaceQuarantined replaces OPA's complete quarantine document.
//
// Phase 5 startup reconciliation will use this to rebuild OPA data from
// SQLite, which remains the persistent source of truth.
func (c *Client) ReplaceQuarantined(
	ctx context.Context,
	spiffeIDs []string,
) error {
	if err := validateContext(ctx); err != nil {
		return err
	}

	document := make(
		map[string]bool,
		len(spiffeIDs),
	)

	for _, spiffeID := range spiffeIDs {
		spiffeID = strings.TrimSpace(spiffeID)

		if !domain.IsKnownWorkloadID(spiffeID) {
			return fmt.Errorf(
				"unknown workload SPIFFE ID %q",
				spiffeID,
			)
		}

		document[spiffeID] = true
	}

	c.dataMu.Lock()
	defer c.dataMu.Unlock()

	return c.putQuarantinedUnlocked(
		ctx,
		document,
	)
}

// ListQuarantined returns the SPIFFE IDs currently stored in OPA.
func (c *Client) ListQuarantined(
	ctx context.Context,
) ([]string, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	c.dataMu.Lock()
	defer c.dataMu.Unlock()

	document, err := c.getQuarantinedUnlocked(ctx)
	if err != nil {
		return nil, err
	}

	spiffeIDs := make(
		[]string,
		0,
		len(document),
	)

	for spiffeID, quarantined := range document {
		if quarantined {
			spiffeIDs = append(
				spiffeIDs,
				spiffeID,
			)
		}
	}

	sort.Strings(spiffeIDs)

	return spiffeIDs, nil
}

func (c *Client) getQuarantinedUnlocked(
	ctx context.Context,
) (map[string]bool, error) {
	var response quarantineResponse

	if err := c.doJSON(
		ctx,
		http.MethodGet,
		c.endpoint(quarantineDataPath),
		nil,
		&response,
	); err != nil {
		return nil, fmt.Errorf(
			"read OPA quarantine data: %w",
			err,
		)
	}

	// OPA omits "result" when the document has not yet been created.
	if response.Result == nil {
		return make(
			map[string]bool,
		), nil
	}

	document := make(
		map[string]bool,
		len(response.Result),
	)

	for spiffeID, quarantined := range response.Result {
		if quarantined {
			document[spiffeID] = true
		}
	}

	return document, nil
}

func (c *Client) putQuarantinedUnlocked(
	ctx context.Context,
	document map[string]bool,
) error {
	if document == nil {
		document = make(
			map[string]bool,
		)
	}

	if err := c.doJSON(
		ctx,
		http.MethodPut,
		c.endpoint(quarantineDataPath),
		document,
		nil,
	); err != nil {
		return fmt.Errorf(
			"write OPA quarantine data: %w",
			err,
		)
	}

	return nil
}

func (c *Client) decisionURL() (
	string,
	error,
) {
	endpoint, err := url.Parse(
		c.endpoint(c.decisionPath),
	)
	if err != nil {
		return "", fmt.Errorf(
			"build OPA decision URL: %w",
			err,
		)
	}

	query := endpoint.Query()
	query.Set(
		"strict-builtin-errors",
		"true",
	)
	endpoint.RawQuery = query.Encode()

	return endpoint.String(), nil
}

func (c *Client) endpoint(
	path string,
) string {
	if !strings.HasPrefix(
		path,
		"/",
	) {
		path = "/" + path
	}

	return c.baseURL + path
}

func (c *Client) doJSON(
	ctx context.Context,
	method string,
	endpoint string,
	requestValue any,
	responseValue any,
) error {
	var requestBody io.Reader

	if requestValue != nil {
		encoded, err := json.Marshal(
			requestValue,
		)
		if err != nil {
			return fmt.Errorf(
				"encode OPA request: %w",
				err,
			)
		}

		requestBody = bytes.NewReader(
			encoded,
		)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		method,
		endpoint,
		requestBody,
	)
	if err != nil {
		return fmt.Errorf(
			"create OPA request: %w",
			err,
		)
	}

	request.Header.Set(
		"Accept",
		"application/json",
	)

	if requestValue != nil {
		request.Header.Set(
			"Content-Type",
			"application/json",
		)
	}

	response, err := c.httpClient.Do(
		request,
	)
	if err != nil {
		return fmt.Errorf(
			"send OPA request: %w",
			err,
		)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	responseBody, err := io.ReadAll(
		io.LimitReader(
			response.Body,
			maxResponseBytes,
		),
	)
	if err != nil {
		return fmt.Errorf(
			"read OPA response: %w",
			err,
		)
	}

	if response.StatusCode < 200 ||
		response.StatusCode >= 300 {
		message := strings.TrimSpace(
			string(responseBody),
		)

		if message == "" {
			message = http.StatusText(
				response.StatusCode,
			)
		}

		return fmt.Errorf(
			"OPA returned HTTP %d: %s",
			response.StatusCode,
			message,
		)
	}

	if responseValue == nil ||
		len(bytes.TrimSpace(responseBody)) == 0 {
		return nil
	}

	if err = json.Unmarshal(
		responseBody,
		responseValue,
	); err != nil {
		return fmt.Errorf(
			"decode OPA response: %w",
			err,
		)
	}

	return nil
}

func validateContext(
	ctx context.Context,
) error {
	if ctx == nil {
		return errors.New(
			"context must not be nil",
		)
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf(
			"context is not usable: %w",
			err,
		)
	}

	return nil
}

type decisionInput struct {
	SPIFFEID string `json:"spiffe_id"`
	Method   string `json:"method"`
	Path     string `json:"path"`
}

type decisionRequest struct {
	Input decisionInput `json:"input"`
}

type decisionResponse struct {
	Result *decisionResult `json:"result"`
}

type decisionResult struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type quarantineResponse struct {
	Result map[string]bool `json:"result"`
}
