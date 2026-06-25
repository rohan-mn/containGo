package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"containgo.local/containgo/internal/platform"
)

const (
	controlPlaneID = "spiffe://containgo.local/ns/containgo/sa/control-plane"
	democtlID      = "spiffe://containgo.local/ns/containgo/sa/democtl"
)

func main() {
	controlURL := flag.String("control-plane", env("CONTROL_PLANE_URL", "https://control-plane:8443"), "control-plane base URL")
	flag.Parse()
	if flag.NArg() == 0 {
		usage()
		os.Exit(2)
	}
	client := platform.MTLSHTTPClient(platform.DefaultIdentityFiles(), controlPlaneID, 15*time.Second).HTTPClient()
	command := flag.Arg(0)
	path := "/v1/workloads"
	method := http.MethodGet
	if command == "incidents" {
		path = "/v1/incidents"
	} else if command == "events" {
		path = "/v1/events?limit=20"
	} else if (command == "release" || command == "reset-risk") && flag.NArg() == 2 {
		path = "/v1/workloads/" + flag.Arg(1) + "/" + command
		method = http.MethodPost
	} else if command != "status" {
		usage()
		os.Exit(2)
	}
	result, err := platform.DoRequest(context.Background(), client, method, strings.TrimRight(*controlURL, "/")+path, nil, nil, democtlID)
	if err != nil {
		log.Fatal(err)
	}
	var pretty any
	if json.Unmarshal(result.Body, &pretty) == nil {
		data, _ := json.MarshalIndent(pretty, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Println(string(result.Body))
	}
	if result.StatusCode >= 300 {
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: democtl [flags] status|incidents|events|release <workload>|reset-risk <workload>")
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
