package dashboard

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"strings"
	"time"

	"containgo.local/containgo/internal/domain"
)

//go:embed web/templates.html web/assets/*
var dashboardWeb embed.FS

func loadTemplates() (*template.Template, error) {
	functions := template.FuncMap{
		"formatTime":       formatTime,
		"formatTimePtr":    formatTimePtr,
		"statusClass":      statusClass,
		"isQuarantined":    isQuarantined,
		"prettyJSON":       prettyJSON,
		"shortSPIFFE":      shortSPIFFE,
		"incidentPoints":   incidentPoints,
		"eventPoints":      eventPoints,
		"humanAuditAction": humanAuditAction,
	}

	templates, err := template.New("dashboard").Funcs(functions).ParseFS(
		dashboardWeb,
		"web/templates.html",
	)
	if err != nil {
		return nil, fmt.Errorf("parse dashboard templates: %w", err)
	}

	return templates, nil
}

func assetsFileSystem() (fs.FS, error) {
	assets, err := fs.Sub(dashboardWeb, "web/assets")
	if err != nil {
		return nil, fmt.Errorf("open embedded dashboard assets: %w", err)
	}

	return assets, nil
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return "—"
	}

	return value.Local().Format("02 Jan 2006, 15:04:05")
}

func formatTimePtr(value *time.Time) string {
	if value == nil || value.IsZero() {
		return "—"
	}

	return formatTime(*value)
}

func statusClass(status domain.WorkloadStatus) string {
	if status == domain.WorkloadStatusQuarantined {
		return "badge-danger"
	}

	return "badge-success"
}

func isQuarantined(workload domain.Workload) bool {
	return workload.IsQuarantined()
}

func prettyJSON(value json.RawMessage) string {
	if len(value) == 0 {
		return "{}"
	}

	var output bytes.Buffer
	if err := json.Indent(&output, value, "", "  "); err != nil {
		return string(value)
	}

	return output.String()
}

func shortSPIFFE(spiffeID string) string {
	if name, found := domain.KnownWorkloadName(spiffeID); found {
		return name
	}

	spiffeID = strings.TrimSpace(spiffeID)
	if spiffeID == "" {
		return "—"
	}

	return spiffeID
}

func incidentPoints(incident domain.Incident) int {
	return incident.TotalReasonPoints()
}

func eventPoints(event domain.StoredEvent) int {
	return event.TotalContributionPoints()
}

func humanAuditAction(action domain.AuditAction) string {
	words := strings.Split(string(action), "_")
	for index, word := range words {
		if word == "opa" {
			words[index] = "OPA"
			continue
		}

		if word != "" {
			words[index] = strings.ToUpper(word[:1]) + word[1:]
		}
	}

	return strings.Join(words, " ")
}
