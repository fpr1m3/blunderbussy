package main

import (
	"fmt"
	"sync"

	"github.com/fpr1m3/go-msf-rpc/rpc"
)

// MSFClient wraps the go-msf-rpc client with connection management
type MSFClient struct {
	mu        sync.RWMutex
	msf       *rpc.Metasploit
	host      string
	user      string
	pass      string
	connected bool
}

// NewMSFClient creates a new MSF client wrapper
func NewMSFClient() *MSFClient {
	return &MSFClient{
		connected: false,
	}
}

// Connect establishes a connection to msfrpcd
func (c *MSFClient) Connect(host, user, pass string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Disconnect existing connection if any
	if c.msf != nil {
		c.msf.Logout()
		c.msf = nil
		c.connected = false
	}

	msf, err := rpc.New(host, user, pass)
	if err != nil {
		return fmt.Errorf("failed to connect to msfrpcd: %w", err)
	}

	c.msf = msf
	c.host = host
	c.user = user
	c.pass = pass
	c.connected = true

	return nil
}

// Disconnect closes the connection to msfrpcd
func (c *MSFClient) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.msf != nil {
		err := c.msf.Logout()
		c.msf = nil
		c.connected = false
		return err
	}
	return nil
}

// IsConnected returns the connection status
func (c *MSFClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// GetHost returns the current host
func (c *MSFClient) GetHost() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.host
}

// getMSF returns the underlying Metasploit client (thread-safe)
func (c *MSFClient) getMSF() (*rpc.Metasploit, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.msf == nil {
		return nil, fmt.Errorf("not connected to msfrpcd")
	}
	return c.msf, nil
}

// CoreVersion returns the Metasploit version info
func (c *MSFClient) CoreVersion() (*VersionResponse, error) {
	msf, err := c.getMSF()
	if err != nil {
		return nil, err
	}

	res, err := msf.CoreVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get core version: %w", err)
	}

	return &VersionResponse{
		Version: res.Version,
		Ruby:    res.Ruby,
		API:     res.Api,
	}, nil
}

// ModuleExploits returns all exploit modules
func (c *MSFClient) ModuleExploits() ([]string, error) {
	msf, err := c.getMSF()
	if err != nil {
		return nil, err
	}

	res, err := msf.ModuleExploits()
	if err != nil {
		return nil, fmt.Errorf("failed to list exploits: %w", err)
	}

	return res.Modules, nil
}

// ModuleAuxiliary returns all auxiliary modules
func (c *MSFClient) ModuleAuxiliary() ([]string, error) {
	msf, err := c.getMSF()
	if err != nil {
		return nil, err
	}

	res, err := msf.ModuleAuxiliary()
	if err != nil {
		return nil, fmt.Errorf("failed to list auxiliary modules: %w", err)
	}

	return res.Modules, nil
}

// ModulePost returns all post modules
func (c *MSFClient) ModulePost() ([]string, error) {
	msf, err := c.getMSF()
	if err != nil {
		return nil, err
	}

	res, err := msf.ModulePost()
	if err != nil {
		return nil, fmt.Errorf("failed to list post modules: %w", err)
	}

	return res.Modules, nil
}

// ModulePayloads returns all payload modules
func (c *MSFClient) ModulePayloads() ([]string, error) {
	msf, err := c.getMSF()
	if err != nil {
		return nil, err
	}

	res, err := msf.ModulePayloads()
	if err != nil {
		return nil, fmt.Errorf("failed to list payloads: %w", err)
	}

	return res.Modules, nil
}

// ModuleInfo returns detailed information about a module
func (c *MSFClient) ModuleInfo(moduleType, moduleName string) (*ModuleInfoResponse, error) {
	msf, err := c.getMSF()
	if err != nil {
		return nil, err
	}

	res, err := msf.ModuleInfo(moduleType, moduleName)
	if err != nil {
		return nil, fmt.Errorf("failed to get module info: %w", err)
	}

	return &ModuleInfoResponse{
		Name:        res.Name,
		Description: res.Description,
		License:     res.License,
		FilePath:    res.FilePath,
		Version:     res.Version,
		Rank:        res.Rank,
		References:  res.References,
		Authors:     res.Authors,
	}, nil
}

// ModuleOptions returns the options for a module
func (c *MSFClient) ModuleOptions(moduleType, moduleName string) (ModuleOptionsResponse, error) {
	msf, err := c.getMSF()
	if err != nil {
		return nil, err
	}

	res, err := msf.ModuleOptions(moduleType, moduleName)
	if err != nil {
		return nil, fmt.Errorf("failed to get module options: %w", err)
	}

	// Convert to our response type
	options := make(ModuleOptionsResponse)
	for key, opt := range res {
		options[key] = ModuleOption{
			Type:     opt.Type,
			Required: opt.Required,
			Advanced: opt.Advanced,
			Evasion:  opt.Evasion,
			Desc:     opt.Desc,
			Default:  opt.Default,
			Enums:    opt.Enums,
		}
	}

	return options, nil
}

// ModuleExecute executes a module
func (c *MSFClient) ModuleExecute(moduleType, moduleName string, options map[string]string) (uint32, error) {
	msf, err := c.getMSF()
	if err != nil {
		return 0, err
	}

	res, err := msf.ModuleExecute(moduleType, moduleName, options)
	if err != nil {
		return 0, fmt.Errorf("failed to execute module: %w", err)
	}

	return res.JobId, nil
}

// ModuleCompatiblePayloads returns compatible payloads for a module
func (c *MSFClient) ModuleCompatiblePayloads(moduleName string) ([]string, error) {
	msf, err := c.getMSF()
	if err != nil {
		return nil, err
	}

	res, err := msf.ModuleCompatiblePayloads(moduleName)
	if err != nil {
		return nil, fmt.Errorf("failed to get compatible payloads: %w", err)
	}

	return res.Payloads, nil
}

// SessionList returns all active sessions
func (c *MSFClient) SessionList() ([]SessionInfo, error) {
	msf, err := c.getMSF()
	if err != nil {
		return nil, err
	}

	res, err := msf.SessionList()
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}

	sessions := make([]SessionInfo, 0, len(res))
	for id, sess := range res {
		sessions = append(sessions, SessionInfo{
			ID:          id,
			Type:        sess.Type,
			TunnelLocal: sess.TunnelLocal,
			TunnelPeer:  sess.TunnelPeer,
			ViaExploit:  sess.ViaExploit,
			ViaPayload:  sess.ViaPayload,
			Description: sess.Description,
			Info:        sess.Info,
			Workspace:   sess.Workspace,
			SessionHost: sess.SessionHost,
			SessionPort: sess.SessionPort,
			Username:    sess.Username,
			UUID:        sess.UUID,
			ExploitUUID: sess.ExploitUUID,
		})
	}

	return sessions, nil
}

// SessionExecute executes a command in a shell session
func (c *MSFClient) SessionExecute(sessionID uint32, command string) (string, error) {
	msf, err := c.getMSF()
	if err != nil {
		return "", err
	}

	output, err := msf.SessionExecute(sessionID, command)
	if err != nil {
		return "", fmt.Errorf("failed to execute session command: %w", err)
	}

	return output, nil
}

// SessionMeterpreterRunSingle runs a Meterpreter command
func (c *MSFClient) SessionMeterpreterRunSingle(sessionID uint32, command string) (string, error) {
	msf, err := c.getMSF()
	if err != nil {
		return "", err
	}

	res, err := msf.SessionMeterpreterRunSingle(sessionID, command)
	if err != nil {
		return "", fmt.Errorf("failed to run meterpreter command: %w", err)
	}

	return res.Result, nil
}

// SessionMeterpreterRead reads output from a Meterpreter session
func (c *MSFClient) SessionMeterpreterRead(sessionID uint32) (string, error) {
	msf, err := c.getMSF()
	if err != nil {
		return "", err
	}

	res, err := msf.SessionMeterpreterRead(sessionID)
	if err != nil {
		return "", fmt.Errorf("failed to read meterpreter output: %w", err)
	}

	return res.Data, nil
}

// SessionShellUpgrade upgrades a shell session to Meterpreter
func (c *MSFClient) SessionShellUpgrade(sessionID uint32, lhost string, lport uint32) (string, error) {
	msf, err := c.getMSF()
	if err != nil {
		return "", err
	}

	res, err := msf.SessionShellUpgrade(sessionID, lhost, lport)
	if err != nil {
		return "", fmt.Errorf("failed to upgrade session: %w", err)
	}

	return res.Result, nil
}

// JobList returns all running jobs
func (c *MSFClient) JobList() ([]JobInfo, error) {
	msf, err := c.getMSF()
	if err != nil {
		return nil, err
	}

	res, err := msf.JobList()
	if err != nil {
		return nil, fmt.Errorf("failed to list jobs: %w", err)
	}

	jobs := make([]JobInfo, 0, len(res))
	for id, name := range res {
		jobs = append(jobs, JobInfo{
			ID:   id,
			Name: name,
		})
	}

	return jobs, nil
}

// JobStop stops a running job
func (c *MSFClient) JobStop(jobID string) (string, error) {
	msf, err := c.getMSF()
	if err != nil {
		return "", err
	}

	res, err := msf.JobStop(jobID)
	if err != nil {
		return "", fmt.Errorf("failed to stop job: %w", err)
	}

	return res.Result, nil
}
