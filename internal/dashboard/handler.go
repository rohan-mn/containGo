package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"containgo.local/containgo/internal/domain"
)

const dashboardRequestTimeout = 5 * time.Second

// App serves the browser dashboard.
type App struct {
	client       *Client
	reportClient *ReportClient
	templates    *template.Template
	csrf         *CSRFProtector
	demoToken    string
}

// NewApp creates the dashboard application.
func NewApp(
	client *Client,
	secureCookie bool,
) (*App, error) {
	return NewAppWithDemo(
		client,
		nil,
		secureCookie,
		"",
	)
}

// NewAppWithDemo creates the dashboard with the guided demo console enabled.
func NewAppWithDemo(
	client *Client,
	reportClient *ReportClient,
	secureCookie bool,
	demoToken string,
) (*App, error) {
	if client == nil {
		return nil, errors.New("dashboard client must not be nil")
	}

	templates, err := loadTemplates()
	if err != nil {
		return nil, err
	}

	return &App{
		client:       client,
		reportClient: reportClient,
		templates:    templates,
		csrf:         NewCSRFProtector(secureCookie),
		demoToken:    strings.TrimSpace(demoToken),
	}, nil
}

// Handler returns the complete browser dashboard route tree.
func (a *App) Handler() (http.Handler, error) {
	assets, err := assetsFileSystem()
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.Handle(
		"/assets/",
		http.StripPrefix(
			"/assets/",
			http.FileServer(http.FS(assets)),
		),
	)
	mux.HandleFunc("/healthz", a.handleHealth)
	mux.HandleFunc("/readyz", a.handleReady)
	mux.HandleFunc("/audit", a.handleAudit)
	mux.HandleFunc("/architecture", a.handleArchitecture)
	mux.HandleFunc("/demo", a.handleDemo)
	mux.HandleFunc("/demo/", a.handleDemoRoute)
	mux.HandleFunc("/demo-api/v1/", a.handleDemoAPI)
	mux.HandleFunc("/workloads/", a.handleWorkloadRoute)
	mux.HandleFunc("/", a.handleIndex)

	return securityHeaders(
		recoverMiddleware(mux),
	), nil
}

type basePage struct {
	Title          string
	CSRFToken      string
	Notice         string
	Error          string
	GeneratedAt    time.Time
	AutoRefresh    bool
	RefreshSeconds int
}

type summaryView struct {
	TotalWorkloads int
	Active         int
	Quarantined    int
	TotalRisk      int
	DeniedRequests int
}

type dashboardPage struct {
	basePage
	Summary     summaryView
	Workloads   []domain.Workload
	RecentAudit []domain.AuditRecord
}

type riskEvidence struct {
	OccurredAt time.Time
	RequestID  string
	Path       string
	Decision   domain.SecurityDecision
	Rule       domain.RiskRule
	Points     int
	Reason     string
}

type workloadPage struct {
	basePage
	Workload  domain.Workload
	Evidence  []riskEvidence
	Events    []domain.StoredEvent
	Incidents []domain.Incident
	Audit     []domain.AuditRecord
}

type auditPage struct {
	basePage
	Records []domain.AuditRecord
}

func (a *App) handleIndex(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}

	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}

	ctx, cancel := context.WithTimeout(
		request.Context(),
		dashboardRequestTimeout,
	)
	defer cancel()

	workloads, err := a.client.ListWorkloads(ctx)
	if err != nil {
		a.renderFailure(writer, request, http.StatusBadGateway, err)
		return
	}

	auditRecords, err := a.client.ListAudit(ctx, "", 20)
	if err != nil {
		a.renderFailure(writer, request, http.StatusBadGateway, err)
		return
	}

	sort.Slice(workloads, func(left, right int) bool {
		return workloads[left].Name < workloads[right].Name
	})

	summary := summaryView{
		TotalWorkloads: len(workloads),
	}
	for _, workload := range workloads {
		summary.TotalRisk += workload.RiskScore
		summary.DeniedRequests += workload.DeniedRequests
		if workload.IsQuarantined() {
			summary.Quarantined++
		} else {
			summary.Active++
		}
	}

	base, err := a.basePage(writer, request, "Security overview", true)
	if err != nil {
		writePlainError(writer, http.StatusInternalServerError, err)
		return
	}

	a.render(writer, http.StatusOK, "index", dashboardPage{
		basePage:    base,
		Summary:     summary,
		Workloads:   workloads,
		RecentAudit: auditRecords,
	})
}

func (a *App) handleWorkloadRoute(
	writer http.ResponseWriter,
	request *http.Request,
) {
	remainder := strings.Trim(
		strings.TrimPrefix(request.URL.Path, "/workloads/"),
		"/",
	)
	if remainder == "" {
		http.NotFound(writer, request)
		return
	}

	parts := strings.Split(remainder, "/")
	if len(parts) > 2 {
		http.NotFound(writer, request)
		return
	}

	workloadName, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(workloadName) == "" {
		http.NotFound(writer, request)
		return
	}

	if len(parts) == 1 {
		a.handleWorkload(writer, request, workloadName)
		return
	}

	switch parts[1] {
	case "release":
		a.handleRelease(writer, request, workloadName)
	case "reset-risk":
		a.handleResetRisk(writer, request, workloadName)
	default:
		http.NotFound(writer, request)
	}
}

func (a *App) handleWorkload(
	writer http.ResponseWriter,
	request *http.Request,
	workloadName string,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}

	ctx, cancel := context.WithTimeout(
		request.Context(),
		dashboardRequestTimeout,
	)
	defer cancel()

	workload, err := a.client.FindWorkload(ctx, workloadName)
	if err != nil {
		a.renderFailure(writer, request, statusForClientError(err), err)
		return
	}

	events, err := a.client.ListEvents(ctx, workloadName, 75)
	if err != nil {
		a.renderFailure(writer, request, http.StatusBadGateway, err)
		return
	}

	incidents, err := a.client.ListIncidents(ctx, workloadName, 20)
	if err != nil {
		a.renderFailure(writer, request, http.StatusBadGateway, err)
		return
	}

	auditRecords, err := a.client.ListAudit(ctx, workloadName, 75)
	if err != nil {
		a.renderFailure(writer, request, http.StatusBadGateway, err)
		return
	}

	evidence := make([]riskEvidence, 0)
	for _, event := range events {
		for _, contribution := range event.Contributions {
			evidence = append(evidence, riskEvidence{
				OccurredAt: event.Event.OccurredAt,
				RequestID:  event.Event.RequestID,
				Path:       event.Event.Path,
				Decision:   event.Event.Decision,
				Rule:       contribution.Rule,
				Points:     contribution.Points,
				Reason:     contribution.Reason,
			})
		}
	}

	base, err := a.basePage(
		writer,
		request,
		workload.Name,
		true,
	)
	if err != nil {
		writePlainError(writer, http.StatusInternalServerError, err)
		return
	}

	a.render(writer, http.StatusOK, "workload", workloadPage{
		basePage:  base,
		Workload:  workload,
		Evidence:  evidence,
		Events:    events,
		Incidents: incidents,
		Audit:     auditRecords,
	})
}

func (a *App) handleRelease(
	writer http.ResponseWriter,
	request *http.Request,
	workloadName string,
) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}

	if err := a.csrf.Validate(writer, request); err != nil {
		a.redirectActionError(writer, request, workloadName, err)
		return
	}

	ctx, cancel := context.WithTimeout(
		request.Context(),
		dashboardRequestTimeout,
	)
	defer cancel()

	if _, err := a.client.Release(ctx, workloadName); err != nil {
		a.redirectActionError(writer, request, workloadName, err)
		return
	}

	a.redirectWorkload(
		writer,
		request,
		workloadName,
		"notice",
		"Workload released and removed from quarantine.",
	)
}

func (a *App) handleResetRisk(
	writer http.ResponseWriter,
	request *http.Request,
	workloadName string,
) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}

	if err := a.csrf.Validate(writer, request); err != nil {
		a.redirectActionError(writer, request, workloadName, err)
		return
	}

	ctx, cancel := context.WithTimeout(
		request.Context(),
		dashboardRequestTimeout,
	)
	defer cancel()

	if _, err := a.client.ResetRisk(ctx, workloadName); err != nil {
		a.redirectActionError(writer, request, workloadName, err)
		return
	}

	a.redirectWorkload(
		writer,
		request,
		workloadName,
		"notice",
		"Risk score and rolling request state reset.",
	)
}

func (a *App) handleAudit(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}

	ctx, cancel := context.WithTimeout(
		request.Context(),
		dashboardRequestTimeout,
	)
	defer cancel()

	records, err := a.client.ListAudit(ctx, "", 200)
	if err != nil {
		a.renderFailure(writer, request, http.StatusBadGateway, err)
		return
	}

	base, err := a.basePage(writer, request, "Audit timeline", true)
	if err != nil {
		writePlainError(writer, http.StatusInternalServerError, err)
		return
	}

	a.render(writer, http.StatusOK, "audit", auditPage{
		basePage: base,
		Records:  records,
	})
}

func (a *App) handleHealth(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}

	writeJSON(writer, http.StatusOK, map[string]any{
		"service": "dashboard",
		"status":  "ok",
		"time":    time.Now().UTC(),
	})
}

func (a *App) handleReady(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}

	ctx, cancel := context.WithTimeout(
		request.Context(),
		3*time.Second,
	)
	defer cancel()

	if err := a.client.Check(ctx); err != nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{
			"service":    "dashboard",
			"status":     "not_ready",
			"dependency": "control-plane",
		})
		return
	}

	if a.reportClient != nil {
		if _, err := a.reportClient.Snapshot(ctx); err != nil {
			writeJSON(writer, http.StatusServiceUnavailable, map[string]any{
				"service":    "dashboard",
				"status":     "not_ready",
				"dependency": "report-client",
			})
			return
		}
	}

	writeJSON(writer, http.StatusOK, map[string]any{
		"service": "dashboard",
		"status":  "ready",
		"time":    time.Now().UTC(),
	})
}

func (a *App) basePage(
	writer http.ResponseWriter,
	request *http.Request,
	title string,
	autoRefresh bool,
) (basePage, error) {
	token, err := a.csrf.Token(writer, request)
	if err != nil {
		return basePage{}, err
	}

	return basePage{
		Title:          title,
		CSRFToken:      token,
		Notice:         strings.TrimSpace(request.URL.Query().Get("notice")),
		Error:          strings.TrimSpace(request.URL.Query().Get("error")),
		GeneratedAt:    time.Now().UTC(),
		AutoRefresh:    autoRefresh,
		RefreshSeconds: 15,
	}, nil
}

func (a *App) render(
	writer http.ResponseWriter,
	status int,
	templateName string,
	data any,
) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)

	if err := a.templates.ExecuteTemplate(
		writer,
		templateName,
		data,
	); err != nil {
		return
	}
}

func (a *App) renderFailure(
	writer http.ResponseWriter,
	request *http.Request,
	status int,
	err error,
) {
	base, tokenErr := a.basePage(
		writer,
		request,
		"Dashboard unavailable",
		false,
	)
	if tokenErr != nil {
		writePlainError(writer, status, err)
		return
	}

	base.Error = "A required backend service is currently unavailable. Check the running services and try again."
	a.render(writer, status, "failure", base)
}

func (a *App) redirectActionError(
	writer http.ResponseWriter,
	request *http.Request,
	workloadName string,
	err error,
) {
	a.redirectWorkload(
		writer,
		request,
		workloadName,
		"error",
		err.Error(),
	)
}

func (a *App) redirectWorkload(
	writer http.ResponseWriter,
	request *http.Request,
	workloadName string,
	key string,
	message string,
) {
	target := "/workloads/" + url.PathEscape(workloadName) +
		"?" + url.QueryEscape(key) + "=" + url.QueryEscape(message)

	http.Redirect(
		writer,
		request,
		target,
		http.StatusSeeOther,
	)
}

func statusForClientError(err error) int {
	var apiError *APIError
	if errors.As(err, &apiError) && apiError.StatusCode == http.StatusNotFound {
		return http.StatusNotFound
	}

	return http.StatusBadGateway
}

func methodNotAllowed(
	writer http.ResponseWriter,
	method string,
) {
	writer.Header().Set("Allow", method)
	writePlainError(
		writer,
		http.StatusMethodNotAllowed,
		fmt.Errorf("only %s is supported", method),
	)
}

func writePlainError(
	writer http.ResponseWriter,
	status int,
	err error,
) {
	http.Error(writer, err.Error(), status)
}

func writeJSON(
	writer http.ResponseWriter,
	status int,
	value any,
) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		defer func() {
			if recover() != nil {
				writePlainError(
					writer,
					http.StatusInternalServerError,
					errors.New("internal server error"),
				)
			}
		}()

		next.ServeHTTP(writer, request)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		writer.Header().Set(
			"Content-Security-Policy",
			"default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
		)
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set(
			"Permissions-Policy",
			"camera=(), microphone=(), geolocation=()",
		)

		next.ServeHTTP(writer, request)
	})
}
