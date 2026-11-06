package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	hcore "github.com/ne-tort/pathology-core/v2/hcore"
	coretray "github.com/ne-tort/pathology-core/v2/hcore/tray"
	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var (
	hostBasePath   string
	hostWorkingDir string
	hostTempDir    string
	hostListen     string
	hostDebug      bool
	hostAppVersion string
	hostUiExe      string
	hostTray       bool
	hostAutostart  bool
	hostLang       string
)

type coreHostLock struct {
	PID       int    `json:"pid"`
	Listen    string `json:"listen"`
	Version   string `json:"version"`
	StartedAt string `json:"started_at"`
	Tray      bool   `json:"tray"`
}

// exitHostAlreadyRunning is reported when the listen address is taken: another
// host won the race. Distinct from 1 so the client does not treat a benign
// double start as a crash.
const exitHostAlreadyRunning = 3

// isBindConflict reports whether err is "this address is already in use".
func isBindConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "bind:") ||
		strings.Contains(msg, "already listening")
}

var commandHostServe = &cobra.Command{
	Use:   "serve",
	Short: "Run pathology-core gRPC host (Setup only, no VPN Start)",
	Long:  "Headless Core Host for Phase 1: binds loopback gRPC and waits for UI or tray clients.",
	Run:   runHostServe,
}

var commandHost = &cobra.Command{
	Use:   "host",
	Short: "Core Host control plane",
}

func init() {
	commandHostServe.Flags().StringVar(&hostBasePath, "base", "", "portable base / app support directory")
	commandHostServe.Flags().StringVar(&hostWorkingDir, "working", "", "working directory (profiles, configs)")
	commandHostServe.Flags().StringVar(&hostTempDir, "temp", "", "temp directory")
	commandHostServe.Flags().StringVar(&hostListen, "listen", "127.0.0.1:17078", "gRPC listen address (loopback only)")
	commandHostServe.Flags().BoolVar(&hostDebug, "debug", false, "enable debug logging and pprof")
	commandHostServe.Flags().StringVar(&hostAppVersion, "app-version", "", "app version for lock-file handshake")
	commandHostServe.Flags().StringVar(&hostUiExe, "ui-exe", "", "Pathology UI executable for tray Open")
	commandHostServe.Flags().BoolVar(&hostTray, "tray", false, "show system tray (Phase 2)")
	commandHostServe.Flags().BoolVar(&hostAutostart, "autostart", false, "OS login autostart (auto-connect, lightweight)")
	commandHostServe.Flags().StringVar(&hostLang, "lang", "en", "fallback tray language (en|ru)")
	commandHostServe.MarkFlagRequired("base")
	commandHostServe.MarkFlagRequired("working")
	commandHostServe.MarkFlagRequired("temp")

	commandHost.AddCommand(commandHostServe)
	mainCommand.AddCommand(commandHost)
}

func runHostServe(cmd *cobra.Command, args []string) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("host serve panic: ", r)
			os.Exit(1)
		}
	}()

	setupStart := time.Now()
	fmt.Fprintf(os.Stderr, "host serve: pid=%d starting setup base=%s working=%s listen=%s\n",
		os.Getpid(), hostBasePath, hostWorkingDir, hostListen)

	// The lock is written only *after* Setup succeeded, i.e. after the gRPC
	// listener is actually bound.
	//
	// It used to be written first "so the UI can attach early". That inverted
	// ownership: a second CLI that lost the bind race still overwrote the
	// winner's lock with its own pid and listen address, so the UI attached to
	// an address nobody served. Starting `sudo pathology` while a non-root host
	// was running produced exactly that — the UI found a lock pointing at a
	// dead pid, tried to kill it, and died on the resulting detached-process
	// state. Whoever publishes the lock must own the listener.
	if err := hcore.Setup(
		&hcore.SetupRequest{
			BasePath:          hostBasePath,
			WorkingDir:        hostWorkingDir,
			TempDir:           hostTempDir,
			FlutterStatusPort: 0,
			Debug:             hostDebug,
			Mode:              hcore.SetupMode_GRPC_NORMAL_INSECURE,
			Listen:            hostListen,
		},
		nil,
	); err != nil {
		// A lost bind race is an expected, non-fatal outcome: another host is
		// already serving. Exit quietly with a distinct code so the client can
		// tell "already running elsewhere" from "crashed".
		log.Error("host serve setup failed: ", err)
		fmt.Fprintf(os.Stderr, "host serve: setup failed after %s: %v\n", time.Since(setupStart), err)
		if isBindConflict(err) {
			os.Exit(exitHostAlreadyRunning)
		}
		os.Exit(1)
	}

	if err := writeCoreHostLock(); err != nil {
		log.Warn("core host lock:", err)
	}
	defer removeCoreHostLock()

	fmt.Fprintf(os.Stderr, "host serve: setup done in %s, listening on %s\n", time.Since(setupStart), hostListen)

	fmt.Printf("Core Host listening on %s (Ctrl+C to stop)\n", hostListen)

	if hostTray {
		coretray.StartTray(coretray.Options{
			UIExe:       hostUiExe,
			BasePath:    hostBasePath,
			Lang:        hostLang,
			UiLifecycle: coretray.UiLifecycleDetached,
		})
	}

	maybeAutoConnectOnHostAutostart()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sigChan:
		fmt.Println("Core Host shutting down (signal)")
	case <-coretray.Done():
		fmt.Println("Core Host shutting down (tray quit)")
	}
	if _, err := hcore.Stop(); err != nil {
		log.Warn("host serve stop:", err)
	}
	hcore.CloseGrpcServer(hcore.SetupMode_GRPC_NORMAL_INSECURE)
}

func maybeAutoConnectOnHostAutostart() {
	if !hostAutostart {
		return
	}
	_, autoConnect := coretray.LoadPrefs(hostBasePath, hostLang)
	if !autoConnect {
		return
	}
	resp, err := hcore.SessionConnect(context.Background())
	if err != nil {
		log.Warn("auto_connect_on_login start:", err)
		return
	}
	// SessionConnect reports "nothing to connect" (no active profile, missing
	// direct config, …) as a status message with a nil error. Swallowing that
	// made a boot-time service look healthy while no tunnel came up: the unit
	// was active, :17078 answered, and the user saw no VPN and no explanation.
	if resp != nil && resp.MessageType == hcore.MessageType_ERROR_BUILDING_CONFIG {
		log.Warn("auto_connect_on_login skipped: ", resp.Message)
	}
}

func writeCoreHostLock() error {
	lock := coreHostLock{
		PID:       os.Getpid(),
		Listen:    hostListen,
		Version:   hostAppVersion,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Tray:      hostTray,
	}
	raw, err := json.Marshal(lock)
	if err != nil {
		return err
	}
	path := filepath.Join(hostBasePath, "core_host.lock")
	return os.WriteFile(path, raw, 0o644)
}

func removeCoreHostLock() {
	path := filepath.Join(hostBasePath, "core_host.lock")
	_ = os.Remove(path)
}
