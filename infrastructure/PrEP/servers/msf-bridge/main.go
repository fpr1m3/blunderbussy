package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Config holds the application configuration
type Config struct {
	MSFHost    string
	MSFPort    string
	MSFUser    string
	MSFPass    string
	BridgePort string
}

// LoadConfig loads configuration from environment variables
func LoadConfig() *Config {
	return &Config{
		MSFHost:    getEnv("MSF_HOST", "msf"),
		MSFPort:    getEnv("MSF_PORT", "55553"),
		MSFUser:    getEnv("MSF_USER", "msf"),
		MSFPass:    getEnv("MSF_PASS", ""),
		BridgePort: getEnv("BRIDGE_PORT", "9997"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("MSF Bridge starting...")

	// Load configuration
	config := LoadConfig()

	// Validate required config
	if config.MSFPass == "" {
		log.Println("Warning: MSF_PASS not set, connection will require explicit credentials")
	}

	// Create MSF client
	client := NewMSFClient()

	// Create handler
	handler := NewHandler(client, config)

	// Set up routes
	mux := http.NewServeMux()

	// Connection management
	mux.HandleFunc("/connect", handler.HandleConnect)
	mux.HandleFunc("/health", handler.HandleHealth)
	mux.HandleFunc("/version", handler.HandleVersion)

	// Module operations
	mux.HandleFunc("/modules/", handler.HandleModules)
	mux.HandleFunc("/module/info", handler.HandleModuleInfo)
	mux.HandleFunc("/module/options", handler.HandleModuleOptions)
	mux.HandleFunc("/module/execute", handler.HandleModuleExecute)
	mux.HandleFunc("/module/payloads/", handler.HandleModulePayloads)

	// Session operations
	mux.HandleFunc("/sessions", handler.HandleSessions)
	mux.HandleFunc("/session/execute", handler.HandleSessionExecute)
	mux.HandleFunc("/session/meterpreter", handler.HandleSessionMeterpreter)
	mux.HandleFunc("/session/upgrade", handler.HandleSessionUpgrade)

	// Job operations
	mux.HandleFunc("/jobs", handler.HandleJobs)
	mux.HandleFunc("/job/stop", handler.HandleJobStop)

	// Create server
	server := &http.Server{
		Addr:         ":" + config.BridgePort,
		Handler:      loggingMiddleware(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("MSF Bridge listening on port %s", config.BridgePort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Auto-connect if credentials are available
	if config.MSFPass != "" {
		go func() {
			// Wait a moment for server to start
			time.Sleep(100 * time.Millisecond)

			host := config.MSFHost
			if !strings.HasPrefix(host, "http") {
				host = "https://" + host + ":" + config.MSFPort
			}

			log.Printf("Auto-connecting to msfrpcd at %s...", host)
			if err := client.Connect(host, config.MSFUser, config.MSFPass); err != nil {
				log.Printf("Auto-connect failed: %v", err)
			} else {
				log.Println("Auto-connect successful")
			}
		}()
	}

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Disconnect from MSF
	if err := client.Disconnect(); err != nil {
		log.Printf("Error disconnecting from MSF: %v", err)
	}

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

// loggingMiddleware logs incoming requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response wrapper to capture status code
		wrapped := &responseWrapper{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		log.Printf("%s %s %d %s", r.Method, r.URL.Path, wrapped.statusCode, time.Since(start))
	})
}

// responseWrapper wraps http.ResponseWriter to capture status code
type responseWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWrapper) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}
