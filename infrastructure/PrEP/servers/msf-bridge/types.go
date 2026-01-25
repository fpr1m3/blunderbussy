package main

// Request types

// ConnectRequest for POST /connect
type ConnectRequest struct {
	Host string `json:"host,omitempty"`
	Port string `json:"port,omitempty"`
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`
}

// ModuleInfoRequest for POST /module/info
type ModuleInfoRequest struct {
	Type   string `json:"type"`
	Module string `json:"module"`
}

// ModuleExecuteRequest for POST /module/execute
type ModuleExecuteRequest struct {
	Type    string            `json:"type"`
	Module  string            `json:"module"`
	Options map[string]string `json:"options"`
}

// SessionExecuteRequest for POST /session/execute
type SessionExecuteRequest struct {
	SessionID uint32 `json:"session_id"`
	Command   string `json:"command"`
}

// SessionMeterpreterRequest for POST /session/meterpreter
type SessionMeterpreterRequest struct {
	SessionID uint32 `json:"session_id"`
	Command   string `json:"command"`
}

// SessionUpgradeRequest for POST /session/upgrade
type SessionUpgradeRequest struct {
	SessionID uint32 `json:"session_id"`
	LHost     string `json:"lhost"`
	LPort     uint32 `json:"lport"`
}

// JobStopRequest for POST /job/stop
type JobStopRequest struct {
	JobID string `json:"job_id"`
}

// Response types

// ErrorResponse for error responses
type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

// HealthResponse for GET /health
type HealthResponse struct {
	Status    string `json:"status"`
	Connected bool   `json:"connected"`
	Host      string `json:"host,omitempty"`
}

// VersionResponse for GET /version
type VersionResponse struct {
	Version string `json:"version"`
	Ruby    string `json:"ruby"`
	API     string `json:"api"`
}

// ModulesResponse for GET /modules/:type
type ModulesResponse struct {
	Modules []string `json:"modules"`
	Count   int      `json:"count"`
}

// ModuleInfoResponse for POST /module/info
type ModuleInfoResponse struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	License     string     `json:"license"`
	FilePath    string     `json:"filepath"`
	Version     string     `json:"version"`
	Rank        string     `json:"rank"`
	References  [][]string `json:"references"`
	Authors     []string   `json:"authors"`
}

// ModuleOptionsResponse for module options
type ModuleOptionsResponse map[string]ModuleOption

// ModuleOption represents a single module option
type ModuleOption struct {
	Type     string      `json:"type"`
	Required bool        `json:"required"`
	Advanced bool        `json:"advanced"`
	Evasion  bool        `json:"evasion"`
	Desc     string      `json:"desc"`
	Default  interface{} `json:"default"`
	Enums    []string    `json:"enums,omitempty"`
}

// ModuleExecuteResponse for POST /module/execute
type ModuleExecuteResponse struct {
	JobID uint32 `json:"job_id"`
}

// PayloadsResponse for GET /module/payloads/:module
type PayloadsResponse struct {
	Payloads []string `json:"payloads"`
	Count    int      `json:"count"`
}

// SessionInfo represents a single session
type SessionInfo struct {
	ID          uint32 `json:"id"`
	Type        string `json:"type"`
	TunnelLocal string `json:"tunnel_local"`
	TunnelPeer  string `json:"tunnel_peer"`
	ViaExploit  string `json:"via_exploit"`
	ViaPayload  string `json:"via_payload"`
	Description string `json:"description"`
	Info        string `json:"info"`
	Workspace   string `json:"workspace"`
	SessionHost string `json:"session_host"`
	SessionPort int    `json:"session_port"`
	Username    string `json:"username"`
	UUID        string `json:"uuid"`
	ExploitUUID string `json:"exploit_uuid"`
}

// SessionsResponse for GET /sessions
type SessionsResponse struct {
	Sessions []SessionInfo `json:"sessions"`
	Count    int           `json:"count"`
}

// SessionExecuteResponse for POST /session/execute
type SessionExecuteResponse struct {
	SessionID uint32 `json:"session_id"`
	Command   string `json:"command"`
	Output    string `json:"output"`
}

// SessionMeterpreterResponse for POST /session/meterpreter
type SessionMeterpreterResponse struct {
	SessionID uint32 `json:"session_id"`
	Command   string `json:"command"`
	Result    string `json:"result"`
}

// SessionUpgradeResponse for POST /session/upgrade
type SessionUpgradeResponse struct {
	SessionID uint32 `json:"session_id"`
	Result    string `json:"result"`
}

// JobInfo represents a single job
type JobInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// JobsResponse for GET /jobs
type JobsResponse struct {
	Jobs  []JobInfo `json:"jobs"`
	Count int       `json:"count"`
}

// JobStopResponse for POST /job/stop
type JobStopResponse struct {
	JobID  string `json:"job_id"`
	Result string `json:"result"`
}

// ConnectResponse for POST /connect
type ConnectResponse struct {
	Status  string `json:"status"`
	Host    string `json:"host"`
	Version string `json:"version,omitempty"`
}
