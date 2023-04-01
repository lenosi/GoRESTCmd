package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
)

// Config represents the application configuration
type Config struct {
	APIKey          string   `yaml:"api_key"`          // The API key used to authenticate requests
	ConcurrentLimit int      `yaml:"concurrent_limit"` // The maximum number of concurrent executions
	Port            int      `yaml:"port"`             // The port number the server listens on
	ServerTLS       bool     `yaml:"server_tls"`       // Whether to use TLS for the server
	ServerCertPath  string   `yaml:"server_cert_path"` // The path to the server's SSL/TLS certificate
	ServerKeyPath   string   `yaml:"server_key_path"`  // The path to the server's SSL/TLS private key
	AllowedCommands []string `yaml:"allowed_commands"` // The list of allowed shell commands
}

// LoadConfig reads a configuration file and returns a Config struct.
// filename: path to the YAML configuration file
// Returns Config struct and error if any occurred.
func LoadConfig(filename string) (Config, error) {
	// First, check if the file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return Config{}, errors.New("config file does not exist")
	}

	// If the file exists, read and parse it
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return Config{}, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}

// Execution represents a command execution request.
type Execution struct {
	Command string   `json:"command"` // Command to execute
	Args    []string `json:"args"`    // Arguments to pass to the command
}

// ExecutionResult holds the result of a command execution.
type ExecutionResult struct {
	Stdout     string `json:"stdout"`     // Standard output of the command
	Stderr     string `json:"stderr"`     // Standard error output of the command
	ReturnCode int    `json:"returnCode"` // Return code of the command
	StartTime  string `json:"startTime"`  // Execution start time (UTC)
	EndTime    string `json:"endTime"`    // Execution end time (UTC)
	Elapsed    string `json:"elapsed"`    // Elapsed time (duration)
	Status     string `json:"status"`     // Execution status ("success" or "failure")
}

// Global variables for managing command executions and results
var (
	config          Config                                 // Server configuration
	mu              sync.Mutex                             // Mutex to protect concurrent access to the maps
	executions      = make(map[int]*exec.Cmd)              // Map of running command executions
	results         = make(map[int]*ExecutionResult)       // Map of command execution results
	apiKey          = "your-api-key"                       // Server configuration
	concurrentLimit = 5                                    // Concurrent executions limit
	semaphore       = make(chan struct{}, concurrentLimit) // Semaphore for limiting concurrent executions
)

// main initializes the server configuration, sets up the API routes, and starts the HTTP server.
//
// main function performs the following steps:
// 1. Load configuration from "config.yaml" into the global `config` variable.
// 2. Set global variables `apiKey` and `concurrentLimit` from the loaded configuration.
// 3. Initialize the `semaphore` with the configured concurrent limit.
// 4. Register the following API route handlers with the necessary authentication and method checks:
//   - POST /execute: Executes a command (handled by executeHandler).
//   - GET /execution/: Retrieves information about a specific command execution (handled by executionHandler).
//   - GET /execution/list: Retrieves a list of all command executions (handled by listHandler).
//   - POST /execution/cancel/: Cancels an ongoing command execution (handled by cancelHandler).
//
// 5. Start the HTTP server on the configured port.
func main() {
	var err error
	var configFile string
	flag.StringVar(&configFile, "c", "config.yaml", "path to config file")
	flag.Parse()

	config, err := LoadConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	apiKey = config.APIKey
	concurrentLimit = config.ConcurrentLimit
	semaphore = make(chan struct{}, config.ConcurrentLimit)

	http.HandleFunc("/execute", authenticate(withMethod("POST", executeHandler)))
	http.HandleFunc("/execution/", authenticate(withMethod("GET", executionHandler)))
	http.HandleFunc("/execution/list", authenticate(withMethod("GET", listHandler)))
	http.HandleFunc("/execution/cancel/", authenticate(withMethod("POST", cancelHandler)))

	serverTLS := config.ServerTLS

	if serverTLS {
		tlsConfig := createTLSConfig()

		server := &http.Server{
			Addr:      fmt.Sprintf(":%d", config.Port),
			TLSConfig: tlsConfig,
		}

		log.Fatal(server.ListenAndServeTLS("", ""))
	} else {
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil))
	}
}

func createTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(config.ServerCertPath, config.ServerKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CurvePreferences: []tls.CurveID{
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
		},
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
	}
}

func authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key != apiKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// isAllowedCommand checks if the given command is allowed to be executed.
// command: the command to check
// Returns true if the command is allowed, false otherwise.
func isAllowedCommand(command string) bool {
	for _, allowedCommand := range config.AllowedCommands {
		if command == allowedCommand {
			return true
		}
	}
	return false
}

func executeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var e Execution
	err := json.NewDecoder(r.Body).Decode(&e)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if !isAllowedCommand(e.Command) {
		http.Error(w, "Command not allowed", http.StatusForbidden)
		return
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "/bin/bash", "-c", fmt.Sprintf("%s %s", e.Command, strings.Join(e.Args, " ")))
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	err = cmd.Start()
	if err != nil {
		http.Error(w, "Failed to start command", http.StatusInternalServerError)
		return
	}

	id := cmd.Process.Pid
	mu.Lock()
	executions[id] = cmd
	results[id] = &ExecutionResult{
		StartTime: time.Now().Format(time.RFC3339),
		Status:    "running",
	}
	mu.Unlock()

	semaphore <- struct{}{}
	go func() {
		defer func() { <-semaphore }()
		stdoutBytes, _ := ioutil.ReadAll(stdout)
		stderrBytes, _ := ioutil.ReadAll(stderr)

		mu.Lock()
		results[id].Stdout = string(stdoutBytes)
		results[id].Stderr = string(stderrBytes)
		results[id].ReturnCode = cmd.ProcessState.ExitCode()
		results[id].EndTime = time.Now().Format(time.RFC3339)
		results[id].Status = "completed"
		mu.Unlock()

		cmd.Wait()
		cancelFunc()
	}()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("%d", id)))
}

func executionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	isResult := strings.HasSuffix(r.URL.Path, "/result")
	isStdout := strings.HasSuffix(r.URL.Path, "/stdout")
	isStderr := strings.HasSuffix(r.URL.Path, "/stderr")

	if !isResult && !isStdout && !isStderr {
		http.Error(w, "Invalid endpoint", http.StatusBadRequest)
		return
	}

	idStr := r.URL.Path[len("/execution/") : len(r.URL.Path)-len("/result")]

	if isStdout {
		idStr = r.URL.Path[len("/execution/") : len(r.URL.Path)-len("/stdout")]
	} else if isStderr {
		idStr = r.URL.Path[len("/execution/") : len(r.URL.Path)-len("/stderr")]
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid execution ID", http.StatusBadRequest)
		return
	}

	mu.Lock()
	result := results[id]
	mu.Unlock()

	if result == nil {
		http.Error(w, "Execution not found", http.StatusNotFound)
		return
	}

	if isStdout {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(result.Stdout))
	} else if isStderr {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(result.Stderr))
	} else {
		if result.EndTime != "" {
			startTime, _ := time.Parse(time.RFC3339, result.StartTime)
			endTime, _ := time.Parse(time.RFC3339, result.EndTime)
			result.Elapsed = endTime.Sub(startTime).String()
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	executionList := make(map[int]string)
	for id, result := range results {
		executionList[id] = result.Status
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(executionList)
}

func cancelHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := r.URL.Path[len("/execution/cancel/"):]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid execution ID", http.StatusBadRequest)
		return
	}

	mu.Lock()
	cmd := executions[id]
	result := results[id]
	mu.Unlock()

	if cmd == nil || result == nil {
		http.Error(w, "Execution not found", http.StatusNotFound)
		return
	}

	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		http.Error(w, "Execution already finished", http.StatusConflict)
		return
	}

	err = cmd.Process.Kill()
	if err != nil {
		http.Error(w, "Failed to cancel execution", http.StatusInternalServerError)
		return
	}

	mu.Lock()
	result.Status = "canceled"
	mu.Unlock()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Execution canceled"))
}

func withMethod(method string, handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handlerFunc(w, r)
	}
}
