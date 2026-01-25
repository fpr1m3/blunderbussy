package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// Handler holds dependencies for HTTP handlers
type Handler struct {
	client *MSFClient
	config *Config
}

// NewHandler creates a new handler with dependencies
func NewHandler(client *MSFClient, config *Config) *Handler {
	return &Handler{
		client: client,
		config: config,
	}
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// writeError writes an error response
func writeError(w http.ResponseWriter, status int, message string, details string) {
	writeJSON(w, status, ErrorResponse{
		Error:   message,
		Details: details,
	})
}

// HandleConnect handles POST /connect
func (h *Handler) HandleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "Use POST")
		return
	}

	var req ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Use defaults if no body provided
		req = ConnectRequest{}
	}

	// Use provided values or fall back to config defaults
	host := req.Host
	if host == "" {
		host = h.config.MSFHost
	}
	user := req.User
	if user == "" {
		user = h.config.MSFUser
	}
	pass := req.Pass
	if pass == "" {
		pass = h.config.MSFPass
	}

	// Construct full URL if needed
	if !strings.HasPrefix(host, "http") {
		port := req.Port
		if port == "" {
			port = h.config.MSFPort
		}
		host = "https://" + host + ":" + port
	}

	if err := h.client.Connect(host, user, pass); err != nil {
		log.Printf("Failed to connect to msfrpcd: %v", err)
		writeError(w, http.StatusServiceUnavailable, "Failed to connect to msfrpcd", err.Error())
		return
	}

	// Get version to confirm connection
	version, err := h.client.CoreVersion()
	versionStr := ""
	if err == nil {
		versionStr = version.Version
	}

	writeJSON(w, http.StatusOK, ConnectResponse{
		Status:  "connected",
		Host:    host,
		Version: versionStr,
	})
}

// HandleHealth handles GET /health
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "Use GET")
		return
	}

	status := "disconnected"
	if h.client.IsConnected() {
		status = "connected"
	}

	writeJSON(w, http.StatusOK, HealthResponse{
		Status:    status,
		Connected: h.client.IsConnected(),
		Host:      h.client.GetHost(),
	})
}

// HandleVersion handles GET /version
func (h *Handler) HandleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "Use GET")
		return
	}

	version, err := h.client.CoreVersion()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Failed to get version", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, version)
}

// HandleModules handles GET /modules/:type
func (h *Handler) HandleModules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "Use GET")
		return
	}

	// Extract module type from path
	path := strings.TrimPrefix(r.URL.Path, "/modules/")
	moduleType := strings.TrimSuffix(path, "/")

	var modules []string
	var err error

	switch moduleType {
	case "exploit", "exploits":
		modules, err = h.client.ModuleExploits()
	case "auxiliary":
		modules, err = h.client.ModuleAuxiliary()
	case "post":
		modules, err = h.client.ModulePost()
	case "payload", "payloads":
		modules, err = h.client.ModulePayloads()
	default:
		writeError(w, http.StatusBadRequest, "Invalid module type", "Valid types: exploit, auxiliary, post, payload")
		return
	}

	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Failed to list modules", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, ModulesResponse{
		Modules: modules,
		Count:   len(modules),
	})
}

// HandleModuleInfo handles POST /module/info
func (h *Handler) HandleModuleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "Use POST")
		return
	}

	var req ModuleInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Type == "" || req.Module == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields", "type and module are required")
		return
	}

	info, err := h.client.ModuleInfo(req.Type, req.Module)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Failed to get module info", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, info)
}

// HandleModuleOptions handles POST /module/options
func (h *Handler) HandleModuleOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "Use POST")
		return
	}

	var req ModuleInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Type == "" || req.Module == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields", "type and module are required")
		return
	}

	options, err := h.client.ModuleOptions(req.Type, req.Module)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Failed to get module options", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, options)
}

// HandleModuleExecute handles POST /module/execute
func (h *Handler) HandleModuleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "Use POST")
		return
	}

	var req ModuleExecuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Type == "" || req.Module == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields", "type and module are required")
		return
	}

	if req.Options == nil {
		req.Options = make(map[string]string)
	}

	jobID, err := h.client.ModuleExecute(req.Type, req.Module, req.Options)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Failed to execute module", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, ModuleExecuteResponse{
		JobID: jobID,
	})
}

// HandleModulePayloads handles GET /module/payloads/:module
func (h *Handler) HandleModulePayloads(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "Use GET")
		return
	}

	// Extract module name from path
	path := strings.TrimPrefix(r.URL.Path, "/module/payloads/")
	moduleName := strings.TrimSuffix(path, "/")

	if moduleName == "" {
		writeError(w, http.StatusBadRequest, "Missing module name", "Provide module name in path")
		return
	}

	payloads, err := h.client.ModuleCompatiblePayloads(moduleName)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Failed to get compatible payloads", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, PayloadsResponse{
		Payloads: payloads,
		Count:    len(payloads),
	})
}

// HandleSessions handles GET /sessions
func (h *Handler) HandleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "Use GET")
		return
	}

	sessions, err := h.client.SessionList()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Failed to list sessions", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SessionsResponse{
		Sessions: sessions,
		Count:    len(sessions),
	})
}

// HandleSessionExecute handles POST /session/execute
func (h *Handler) HandleSessionExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "Use POST")
		return
	}

	var req SessionExecuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Command == "" {
		writeError(w, http.StatusBadRequest, "Missing required field", "command is required")
		return
	}

	output, err := h.client.SessionExecute(req.SessionID, req.Command)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Failed to execute command", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SessionExecuteResponse{
		SessionID: req.SessionID,
		Command:   req.Command,
		Output:    output,
	})
}

// HandleSessionMeterpreter handles POST /session/meterpreter
func (h *Handler) HandleSessionMeterpreter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "Use POST")
		return
	}

	var req SessionMeterpreterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Command == "" {
		writeError(w, http.StatusBadRequest, "Missing required field", "command is required")
		return
	}

	// Run the command
	result, err := h.client.SessionMeterpreterRunSingle(req.SessionID, req.Command)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Failed to run meterpreter command", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SessionMeterpreterResponse{
		SessionID: req.SessionID,
		Command:   req.Command,
		Result:    result,
	})
}

// HandleSessionUpgrade handles POST /session/upgrade
func (h *Handler) HandleSessionUpgrade(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "Use POST")
		return
	}

	var req SessionUpgradeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.LHost == "" || req.LPort == 0 {
		writeError(w, http.StatusBadRequest, "Missing required fields", "lhost and lport are required")
		return
	}

	result, err := h.client.SessionShellUpgrade(req.SessionID, req.LHost, req.LPort)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Failed to upgrade session", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SessionUpgradeResponse{
		SessionID: req.SessionID,
		Result:    result,
	})
}

// HandleJobs handles GET /jobs
func (h *Handler) HandleJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "Use GET")
		return
	}

	jobs, err := h.client.JobList()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Failed to list jobs", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, JobsResponse{
		Jobs:  jobs,
		Count: len(jobs),
	})
}

// HandleJobStop handles POST /job/stop
func (h *Handler) HandleJobStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "Use POST")
		return
	}

	var req JobStopRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.JobID == "" {
		writeError(w, http.StatusBadRequest, "Missing required field", "job_id is required")
		return
	}

	result, err := h.client.JobStop(req.JobID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Failed to stop job", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, JobStopResponse{
		JobID:  req.JobID,
		Result: result,
	})
}
