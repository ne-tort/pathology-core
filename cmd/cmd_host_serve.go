package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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
	fmt.Fprintf(os.Stderr, "host serve: pid=%d starting setup base=%s working=%s\n", os.Getpid(), hostBasePath, hostWorkingDir)

	// Write the lock BEFORE Setup: the UI's cold-spawn readiness check is
	// hello + valid lock. Setup binds gRPC midway but keeps initializing
	// (settings DB, tun heal, services) — with a late lock the UI polls the
	// full 30s timeout even though the listener is already up, and a slow
	// tail (e.g. a bloated LevelDB rewrite) surfaced as multi-minute
	// black-screen startups. An early lock + early bind = attach as soon as
	// the listener answers.
	if err := writeCoreHostLock(); err != nil {
		log.Warn("core host lock:", err)
	}
	defer removeCoreHostLock()

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
		log.Error("host serve setup failed: ", err)
		fmt.Fprintf(os.Stderr, "host serve: setup failed after %s: %v\n", time.Since(setupStart), err)
		os.Exit(1)
	}
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
	if _, err := hcore.SessionConnect(context.Background()); err != nil {
		log.Warn("auto_connect_on_login start:", err)
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
