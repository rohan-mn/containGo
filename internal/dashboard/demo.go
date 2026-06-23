package dashboard

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/reportclient"
)

const demoRequestTimeout = 8 * time.Second

const demoTokenHeader = "X-ContainGo-Demo-Token"

type demoStep struct {
	Number      int
	Title       string
	Description string
	State       string
}

type policyRow struct {
	Workload string
	Allowed  string
	Denied   string
}

type demoState struct {
	GeneratedAt    time.Time             `json:"generated_at"`
	Stage          string                `json:"stage"`
	StageLabel     string                `json:"stage_label"`
	ReportClient   domain.Workload       `json:"report_client"`
	OrderClient    domain.Workload       `json:"order_client"`
	Mode           reportclient.Snapshot `json:"mode"`
	Events         []domain.StoredEvent  `json:"events"`
	Incidents      []domain.Incident     `json:"incidents"`
	AuditRecords   []domain.AuditRecord  `json:"audit_records"`
	EvidencePoints int                   `json:"evidence_points"`
}

type demoPage struct {
	basePage
	State        demoState
	Steps        []demoStep
	PolicyMatrix []policyRow
}

type architecturePage struct {
	basePage
	Workloads []domain.Workload
}

func (a *App) handleDemo(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.URL.Path != "/demo" {
		http.NotFound(writer, request)
		return
	}
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if a.reportClient == nil {
		a.renderFailure(writer, request, http.StatusServiceUnavailable, errors.New("demo controller is not configured"))
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), demoRequestTimeout)
	defer cancel()

	state, err := a.loadDemoState(ctx)
	if err != nil {
		a.renderFailure(writer, request, http.StatusBadGateway, err)
		return
	}

	base, err := a.basePage(writer, request, "End-to-end demo console", true)
	if err != nil {
		writePlainError(writer, http.StatusInternalServerError, err)
		return
	}
	base.RefreshSeconds = 5

	a.render(writer, http.StatusOK, "demo", demoPage{
		basePage: base,
		State:    state,
		Steps:    buildDemoSteps(state),
		PolicyMatrix: []policyRow{
			{Workload: "order-client", Allowed: "GET /api/orders", Denied: "Reports, payment details, admin config"},
			{Workload: "report-client", Allowed: "GET /api/reports", Denied: "Orders, payment details, admin config"},
			{Workload: "quarantined workload", Allowed: "Nothing", Denied: "Every protected endpoint"},
		},
	})
}

func (a *App) handleArchitecture(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.URL.Path != "/architecture" {
		http.NotFound(writer, request)
		return
	}
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), dashboardRequestTimeout)
	defer cancel()

	workloads, err := a.client.ListWorkloads(ctx)
	if err != nil {
		a.renderFailure(writer, request, http.StatusBadGateway, err)
		return
	}
	sort.Slice(workloads, func(left, right int) bool {
		return workloads[left].Name < workloads[right].Name
	})

	base, err := a.basePage(writer, request, "Architecture and security controls", true)
	if err != nil {
		writePlainError(writer, http.StatusInternalServerError, err)
		return
	}

	a.render(writer, http.StatusOK, "architecture", architecturePage{
		basePage:  base,
		Workloads: workloads,
	})
}

func (a *App) handleDemoRoute(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if a.reportClient == nil {
		writePlainError(writer, http.StatusServiceUnavailable, errors.New("demo controller is not configured"))
		return
	}
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	if err := a.csrf.Validate(writer, request); err != nil {
		a.redirectDemo(writer, request, "error", err.Error())
		return
	}

	action := strings.Trim(strings.TrimPrefix(request.URL.Path, "/demo/"), "/")
	ctx, cancel := context.WithTimeout(request.Context(), demoRequestTimeout)
	defer cancel()

	var err error
	var notice string

	switch action {
	case "mode":
		var mode reportclient.Mode
		mode, err = reportclient.ParseMode(request.FormValue("mode"))
		if err == nil {
			_, err = a.reportClient.SetMode(ctx, mode)
		}
		if err == nil {
			notice = fmt.Sprintf("Report Client mode changed to %s.", mode)
		}

	case "release":
		_, err = a.reportClient.SetMode(ctx, reportclient.ModeNormal)
		if err == nil {
			_, err = a.client.Release(ctx, domain.WorkloadNameReportClient)
		}
		if err == nil {
			notice = "Report Client returned to normal mode and was released from quarantine."
		}

	case "reset":
		err = a.resetDemo(ctx)
		if err == nil {
			notice = "Demo reset: normal mode, active risk state, and request counters cleared."
		}

	default:
		http.NotFound(writer, request)
		return
	}

	if err != nil {
		a.redirectDemo(writer, request, "error", err.Error())
		return
	}
	a.redirectDemo(writer, request, "notice", notice)
}

func (a *App) handleDemoAPI(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if !a.requireDemoToken(writer, request) {
		return
	}
	if a.reportClient == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{
			"error": "demo controller is not configured",
		})
		return
	}

	path := strings.Trim(strings.TrimPrefix(request.URL.Path, "/demo-api/v1/"), "/")
	ctx, cancel := context.WithTimeout(request.Context(), demoRequestTimeout)
	defer cancel()

	switch path {
	case "state":
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, http.MethodGet)
			return
		}
		state, err := a.loadDemoState(ctx)
		if err != nil {
			writeJSON(writer, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(writer, http.StatusOK, state)

	case "mode":
		if request.Method != http.MethodPost && request.Method != http.MethodPut {
			writer.Header().Set("Allow", "POST, PUT")
			writeJSON(writer, http.StatusMethodNotAllowed, map[string]any{"error": "use POST or PUT"})
			return
		}
		var input struct {
			Mode string `json:"mode"`
		}
		if err := decodeDemoJSON(request, &input); err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		mode, err := reportclient.ParseMode(input.Mode)
		if err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		snapshot, err := a.reportClient.SetMode(ctx, mode)
		if err != nil {
			writeJSON(writer, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(writer, http.StatusOK, snapshot)

	case "release":
		if request.Method != http.MethodPost {
			methodNotAllowed(writer, http.MethodPost)
			return
		}
		_, err := a.reportClient.SetMode(ctx, reportclient.ModeNormal)
		if err == nil {
			_, err = a.client.Release(ctx, domain.WorkloadNameReportClient)
		}
		if err != nil {
			writeJSON(writer, http.StatusConflict, map[string]any{"error": err.Error()})
			return
		}
		state, stateErr := a.loadDemoState(ctx)
		if stateErr != nil {
			writeJSON(writer, http.StatusOK, map[string]any{"status": "released"})
			return
		}
		writeJSON(writer, http.StatusOK, state)

	case "reset":
		if request.Method != http.MethodPost {
			methodNotAllowed(writer, http.MethodPost)
			return
		}
		if err := a.resetDemo(ctx); err != nil {
			writeJSON(writer, http.StatusConflict, map[string]any{"error": err.Error()})
			return
		}
		state, err := a.loadDemoState(ctx)
		if err != nil {
			writeJSON(writer, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(writer, http.StatusOK, state)

	case "workloads":
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, http.MethodGet)
			return
		}
		workloads, err := a.client.ListWorkloads(ctx)
		if err != nil {
			writeJSON(writer, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"workloads": workloads})

	case "report-client/evidence":
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, http.MethodGet)
			return
		}
		state, err := a.loadDemoState(ctx)
		if err != nil {
			writeJSON(writer, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{
			"workload":      state.ReportClient,
			"events":        state.Events,
			"incidents":     state.Incidents,
			"audit_records": state.AuditRecords,
		})

	default:
		writeJSON(writer, http.StatusNotFound, map[string]any{"error": "route not found"})
	}
}

func (a *App) loadDemoState(ctx context.Context) (demoState, error) {
	if a.reportClient == nil {
		return demoState{}, errors.New("demo controller is not configured")
	}

	workloads, err := a.client.ListWorkloads(ctx)
	if err != nil {
		return demoState{}, fmt.Errorf("list workloads: %w", err)
	}

	var reportWorkload domain.Workload
	var orderWorkload domain.Workload
	for _, workload := range workloads {
		switch workload.Name {
		case domain.WorkloadNameReportClient:
			reportWorkload = workload
		case domain.WorkloadNameOrderClient:
			orderWorkload = workload
		}
	}
	if reportWorkload.Name == "" || orderWorkload.Name == "" {
		return demoState{}, errors.New("order-client or report-client is missing")
	}

	mode, err := a.reportClient.Snapshot(ctx)
	if err != nil {
		return demoState{}, fmt.Errorf("read Report Client mode: %w", err)
	}
	events, err := a.client.ListEvents(ctx, domain.WorkloadNameReportClient, 20)
	if err != nil {
		return demoState{}, fmt.Errorf("list Report Client events: %w", err)
	}
	incidents, err := a.client.ListIncidents(ctx, domain.WorkloadNameReportClient, 10)
	if err != nil {
		return demoState{}, fmt.Errorf("list Report Client incidents: %w", err)
	}
	auditRecords, err := a.client.ListAudit(ctx, domain.WorkloadNameReportClient, 20)
	if err != nil {
		return demoState{}, fmt.Errorf("list Report Client audit: %w", err)
	}

	evidencePoints := 0
	if len(incidents) > 0 {
		evidencePoints = incidents[0].TotalReasonPoints()
	}
	stage, label := deriveDemoStage(reportWorkload, mode, incidents)

	return demoState{
		GeneratedAt:    time.Now().UTC(),
		Stage:          stage,
		StageLabel:     label,
		ReportClient:   reportWorkload,
		OrderClient:    orderWorkload,
		Mode:           mode,
		Events:         events,
		Incidents:      incidents,
		AuditRecords:   auditRecords,
		EvidencePoints: evidencePoints,
	}, nil
}

func deriveDemoStage(
	workload domain.Workload,
	mode reportclient.Snapshot,
	incidents []domain.Incident,
) (string, string) {
	if workload.IsQuarantined() {
		return "quarantined", "Threat contained"
	}
	if mode.Mode == reportclient.ModeAttack {
		return "attacking", "Attack traffic in progress"
	}
	if mode.Mode == reportclient.ModeRapid {
		return "rapid", "Request-rate anomaly in progress"
	}
	if mode.Mode == reportclient.ModePaused {
		return "paused", "Report Client paused"
	}
	if len(incidents) > 0 &&
		incidents[0].Status == domain.IncidentStatusReleased &&
		incidents[0].ReleasedAt != nil &&
		mode.UpdatedAt.Before(incidents[0].ReleasedAt.UTC()) {
		return "recovered", "Released and recovered"
	}
	return "normal", "Normal traffic"
}

func buildDemoSteps(state demoState) []demoStep {
	steps := []demoStep{
		{Number: 1, Title: "Identity established", Description: "SPIRE issues X.509-SVIDs and every connection uses exact SPIFFE-ID authorization.", State: "complete"},
		{Number: 2, Title: "Normal request", Description: "Report Client calls GET /api/reports through the API Gateway and receives HTTP 200.", State: "current"},
		{Number: 3, Title: "Policy violation", Description: "Attack mode calls payment and admin endpoints; OPA returns HTTP 403.", State: "pending"},
		{Number: 4, Title: "Automatic quarantine", Description: "Risk contributions reach the threshold and every protected request is denied.", State: "pending"},
		{Number: 5, Title: "Release and audit", Description: "An authenticated administrator releases the workload while evidence and audit history remain.", State: "pending"},
	}

	switch state.Stage {
	case "attacking", "rapid":
		steps[1].State = "complete"
		steps[2].State = "current"
	case "quarantined":
		steps[1].State = "complete"
		steps[2].State = "complete"
		steps[3].State = "current"
	case "recovered":
		for index := range steps {
			steps[index].State = "complete"
		}
		steps[4].State = "current"
	case "paused":
		steps[1].State = "complete"
	}
	return steps
}

func (a *App) resetDemo(ctx context.Context) error {
	if _, err := a.reportClient.SetMode(ctx, reportclient.ModeNormal); err != nil {
		return err
	}

	workload, err := a.client.FindWorkload(ctx, domain.WorkloadNameReportClient)
	if err != nil {
		return err
	}
	if workload.IsQuarantined() {
		if _, err = a.client.Release(ctx, domain.WorkloadNameReportClient); err != nil {
			return err
		}
	} else if workload.RiskScore > 0 || workload.DeniedRequests > 0 {
		if _, err = a.client.ResetRisk(ctx, domain.WorkloadNameReportClient); err != nil {
			return err
		}
	}
	_, err = a.reportClient.ResetStats(ctx)
	return err
}

func (a *App) requireDemoToken(writer http.ResponseWriter, request *http.Request) bool {
	if strings.TrimSpace(a.demoToken) == "" {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"error": "Postman demo API is disabled"})
		return false
	}
	provided := strings.TrimSpace(request.Header.Get(demoTokenHeader))
	if len(provided) != len(a.demoToken) || subtle.ConstantTimeCompare([]byte(provided), []byte(a.demoToken)) != 1 {
		writeJSON(writer, http.StatusUnauthorized, map[string]any{"error": "missing or invalid demo API token"})
		return false
	}
	return true
}

func decodeDemoJSON(request *http.Request, destination any) error {
	if request.Body == nil {
		return errors.New("request body must not be empty")
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, maxFormBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON body: %w", err)
	}
	return nil
}

func (a *App) redirectDemo(
	writer http.ResponseWriter,
	request *http.Request,
	key string,
	message string,
) {
	target := "/demo?" + url.QueryEscape(key) + "=" + url.QueryEscape(message)
	http.Redirect(writer, request, target, http.StatusSeeOther)
}
