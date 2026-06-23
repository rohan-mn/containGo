package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/reportclient"
	"containgo.local/containgo/internal/workloadidentity"
)

const maxResponseBytes = 1 << 20

type config struct {
	controlPlaneURL string
	reportClientURL string
	timeout         time.Duration
}

type client struct {
	config           config
	controlPlaneHTTP *http.Client
	reportClientHTTP *http.Client
}

type statusSnapshot struct {
	Workloads    []domain.Workload     `json:"workloads"`
	ReportClient reportclient.Snapshot `json:"report_client"`
}

type inspectSnapshot struct {
	Workload     domain.Workload      `json:"workload"`
	Events       []domain.StoredEvent `json:"events"`
	Incidents    []domain.Incident    `json:"incidents"`
	AuditRecords []domain.AuditRecord `json:"audit_records"`
}

func main() {
	rootCtx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	identitySource, err := workloadidentity.New(
		rootCtx,
		workloadidentity.Config{
			ExpectedID: domain.SPIFFEIDDemoctl,
			SocketAddress: environment(
				"SPIFFE_ENDPOINT_SOCKET",
				"",
			),
		},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "democtl: create Workload API source: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		_ = identitySource.Close()
	}()

	controlPlaneTLS, err := identitySource.ClientTLSConfig(
		domain.SPIFFEIDControlPlane,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "democtl: create Control Plane SPIFFE TLS: %v\n", err)
		os.Exit(1)
	}

	reportClientTLS, err := identitySource.ClientTLSConfig(
		domain.SPIFFEIDReportClient,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "democtl: create Report Client SPIFFE TLS: %v\n", err)
		os.Exit(1)
	}

	configuration := config{
		controlPlaneURL: strings.TrimRight(
			environment(
				"CONTAINGO_CONTROL_PLANE_URL",
				"https://127.0.0.1:8090",
			),
			"/",
		),
		reportClientURL: strings.TrimRight(
			environment(
				"CONTAINGO_REPORT_CLIENT_CONTROL_URL",
				"https://127.0.0.1:8072",
			),
			"/",
		),
		timeout: 5 * time.Second,
	}

	cli := &client{
		config: configuration,
		controlPlaneHTTP: &http.Client{
			Timeout: configuration.timeout,
			Transport: spiffeTransport(
				controlPlaneTLS,
				configuration.timeout,
			),
		},
		reportClientHTTP: &http.Client{
			Timeout: configuration.timeout,
			Transport: spiffeTransport(
				reportClientTLS,
				configuration.timeout,
			),
		},
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(
		rootCtx,
		configuration.timeout,
	)
	defer cancel()

	command := strings.ToLower(strings.TrimSpace(os.Args[1]))

	switch command {
	case "status":
		err = cli.status(ctx)

	case "status-json":
		err = cli.statusJSON(ctx)

	case "inspect-json":
		if len(os.Args) != 3 {
			err = errors.New("usage: democtl inspect-json <workload-name>")
			break
		}
		err = cli.inspectJSON(ctx, os.Args[2])

	case "normal":
		err = cli.setMode(ctx, reportclient.ModeNormal)

	case "attack":
		err = cli.setMode(ctx, reportclient.ModeAttack)

	case "rapid":
		err = cli.setMode(ctx, reportclient.ModeRapid)

	case "pause", "paused":
		err = cli.setMode(ctx, reportclient.ModePaused)

	case "release":
		if len(os.Args) != 3 {
			err = errors.New("usage: democtl release <workload-name>")
			break
		}
		err = cli.workloadAction(ctx, os.Args[2], "release")

	case "reset-risk":
		if len(os.Args) != 3 {
			err = errors.New("usage: democtl reset-risk <workload-name>")
			break
		}
		err = cli.workloadAction(ctx, os.Args[2], "reset-risk")

	case "help", "-h", "--help":
		usage()
		return

	default:
		err = fmt.Errorf("unknown command %q", command)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "democtl: %v\n", err)
		os.Exit(1)
	}
}

func spiffeTransport(
	tlsConfig *tls.Config,
	timeout time.Duration,
) *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       tlsConfig.Clone(),
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       60 * time.Second,
	}
}

func (c *client) status(ctx context.Context) error {
	snapshot, err := c.readStatus(ctx)
	if err != nil {
		return err
	}

	writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "WORKLOAD\tSTATUS\tRISK\tDENIED\tLAST SEEN")

	for _, workload := range snapshot.Workloads {
		lastSeen := "-"
		if workload.LastSeenAt != nil {
			lastSeen = workload.LastSeenAt.Local().Format(time.RFC3339)
		}

		fmt.Fprintf(
			writer,
			"%s\t%s\t%d\t%d\t%s\n",
			workload.Name,
			workload.Status,
			workload.RiskScore,
			workload.DeniedRequests,
			lastSeen,
		)
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("write status table: %w", err)
	}

	mode := snapshot.ReportClient
	fmt.Printf("\nReport Client mode: %s\n", mode.Mode)
	fmt.Printf(
		"Requests: total=%d success=%d forbidden=%d failed=%d\n",
		mode.TotalRequests,
		mode.Successful,
		mode.Forbidden,
		mode.Failures,
	)

	if mode.LastPath != "" {
		fmt.Printf(
			"Last request: path=%s status=%d error=%s\n",
			mode.LastPath,
			mode.LastStatus,
			valueOrDash(mode.LastError),
		)
	}

	return nil
}

func (c *client) readStatus(ctx context.Context) (statusSnapshot, error) {
	var workloadResponse struct {
		Workloads []domain.Workload `json:"workloads"`
	}

	if err := c.doJSON(
		ctx,
		c.controlPlaneHTTP,
		http.MethodGet,
		c.config.controlPlaneURL+"/v1/workloads",
		nil,
		&workloadResponse,
	); err != nil {
		return statusSnapshot{}, fmt.Errorf("read workload status: %w", err)
	}

	sort.Slice(workloadResponse.Workloads, func(left, right int) bool {
		return workloadResponse.Workloads[left].Name < workloadResponse.Workloads[right].Name
	})

	var mode reportclient.Snapshot
	if err := c.doJSON(
		ctx,
		c.reportClientHTTP,
		http.MethodGet,
		c.config.reportClientURL+"/v1/mode",
		nil,
		&mode,
	); err != nil {
		return statusSnapshot{}, fmt.Errorf("read Report Client mode: %w", err)
	}

	return statusSnapshot{
		Workloads:    workloadResponse.Workloads,
		ReportClient: mode,
	}, nil
}

func (c *client) statusJSON(ctx context.Context) error {
	snapshot, err := c.readStatus(ctx)
	if err != nil {
		return err
	}

	return writePrettyJSON(snapshot)
}

func (c *client) inspectJSON(
	ctx context.Context,
	workload string,
) error {
	workload = strings.TrimSpace(workload)
	if !isKnownWorkloadName(workload) {
		return fmt.Errorf("unknown workload name %q", workload)
	}

	baseURL := fmt.Sprintf(
		"%s/v1/workloads/%s",
		c.config.controlPlaneURL,
		workload,
	)

	var snapshot inspectSnapshot
	if err := c.doJSON(
		ctx,
		c.controlPlaneHTTP,
		http.MethodGet,
		baseURL,
		nil,
		&snapshot.Workload,
	); err != nil {
		return fmt.Errorf("read workload: %w", err)
	}

	var eventResponse struct {
		Events []domain.StoredEvent `json:"events"`
	}
	if err := c.doJSON(
		ctx,
		c.controlPlaneHTTP,
		http.MethodGet,
		baseURL+"/events?limit=100",
		nil,
		&eventResponse,
	); err != nil {
		return fmt.Errorf("read workload events: %w", err)
	}
	snapshot.Events = eventResponse.Events

	var incidentResponse struct {
		Incidents []domain.Incident `json:"incidents"`
	}
	if err := c.doJSON(
		ctx,
		c.controlPlaneHTTP,
		http.MethodGet,
		baseURL+"/incidents?limit=50",
		nil,
		&incidentResponse,
	); err != nil {
		return fmt.Errorf("read workload incidents: %w", err)
	}
	snapshot.Incidents = incidentResponse.Incidents

	var auditResponse struct {
		AuditRecords []domain.AuditRecord `json:"audit_records"`
	}
	if err := c.doJSON(
		ctx,
		c.controlPlaneHTTP,
		http.MethodGet,
		baseURL+"/audit?limit=100",
		nil,
		&auditResponse,
	); err != nil {
		return fmt.Errorf("read workload audit records: %w", err)
	}
	snapshot.AuditRecords = auditResponse.AuditRecords

	return writePrettyJSON(snapshot)
}

func writePrettyJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("encode JSON output: %w", err)
	}

	return nil
}

func (c *client) setMode(
	ctx context.Context,
	mode reportclient.Mode,
) error {
	var response reportclient.Snapshot

	if err := c.doJSON(
		ctx,
		c.reportClientHTTP,
		http.MethodPost,
		c.config.reportClientURL+"/v1/mode",
		map[string]string{
			"mode": string(mode),
		},
		&response,
	); err != nil {
		return fmt.Errorf("set Report Client mode: %w", err)
	}

	fmt.Printf("Report Client mode set to %s\n", response.Mode)
	return nil
}

func (c *client) workloadAction(
	ctx context.Context,
	workload string,
	action string,
) error {
	workload = strings.TrimSpace(workload)
	if !isKnownWorkloadName(workload) {
		return fmt.Errorf("unknown workload name %q", workload)
	}

	var response json.RawMessage
	if err := c.doJSON(
		ctx,
		c.controlPlaneHTTP,
		http.MethodPost,
		fmt.Sprintf(
			"%s/v1/workloads/%s/%s",
			c.config.controlPlaneURL,
			workload,
			action,
		),
		nil,
		&response,
	); err != nil {
		return fmt.Errorf("%s workload: %w", action, err)
	}

	var pretty bytes.Buffer
	if json.Indent(&pretty, response, "", "  ") == nil {
		fmt.Println(pretty.String())
	} else {
		fmt.Println(string(response))
	}

	return nil
}

func (c *client) doJSON(
	ctx context.Context,
	httpClient *http.Client,
	method string,
	endpoint string,
	requestValue any,
	responseValue any,
) error {
	var requestBody io.Reader

	if requestValue != nil {
		encoded, err := json.Marshal(requestValue)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		requestBody = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		method,
		endpoint,
		requestBody,
	)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	request.Header.Set("Accept", "application/json")
	if requestValue != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	if httpClient == nil {
		return errors.New("HTTP client is not configured")
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	body, err := io.ReadAll(
		io.LimitReader(response.Body, maxResponseBytes),
	)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = http.StatusText(response.StatusCode)
		}
		return fmt.Errorf("HTTP %d: %s", response.StatusCode, message)
	}

	if responseValue == nil || len(bytes.TrimSpace(body)) == 0 {
		return nil
	}

	if raw, ok := responseValue.(*json.RawMessage); ok {
		*raw = append((*raw)[:0], body...)
		return nil
	}

	if err = json.Unmarshal(body, responseValue); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

func environment(name string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func isKnownWorkloadName(name string) bool {
	switch name {
	case domain.WorkloadNameAPIGateway,
		domain.WorkloadNameProtectedAPI,
		domain.WorkloadNameControlPlane,
		domain.WorkloadNameOrderClient,
		domain.WorkloadNameReportClient,
		domain.WorkloadNameDemoctl,
		domain.WorkloadNameDashboard:
		return true
	default:
		return false
	}
}

func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func usage() {
	fmt.Print(`ContainGo demo control CLI

Usage:
  democtl status
  democtl status-json
  democtl inspect-json <workload-name>
  democtl normal
  democtl attack
  democtl rapid
  democtl pause
  democtl release <workload-name>
  democtl reset-risk <workload-name>

Examples:
  democtl status
  democtl status-json
  democtl inspect-json report-client
  democtl attack
  democtl release report-client
  democtl normal
`)
}
