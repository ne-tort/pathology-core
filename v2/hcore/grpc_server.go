package hcore

/*
#include "stdint.h"
*/

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"

	"net"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	sync "sync"
	"time"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/ne-tort/pathology-core/v2/db"
	"github.com/ne-tort/pathology-core/v2/ezytel"
	hcommon "github.com/ne-tort/pathology-core/v2/hcommon"
	"github.com/ne-tort/pathology-core/v2/hello"
	hutils "github.com/ne-tort/pathology-core/v2/hutils"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
)

type CoreService struct {
	UnimplementedCoreServer
}

// grpcKeepaliveOptions tunes the server for the Flutter UI client's
// keepalive (30s pings, see CoreTransportOptions in the app repo).
//
// grpc-go defaults treat any ping sooner than 5 minutes as a policy
// violation and kill the connection after 2 strikes ("too_many_pings"
// GOAWAY) — which tore the UI<->core HTTP/2 connection every ~3 minutes,
// failing in-flight RPCs (session disconnect surfaced as
// "startFailed - HTTP/2 Connection error") and churning every stream.
func grpcKeepaliveOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			// UI pings every 30s; anything >= its interval is fine.
			MinTime: 10 * time.Second,
			// localhost UI link: pings with no open stream are harmless.
			PermitWithoutStream: true,
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			// Liveness from the server side; generous vs. the client's own pings.
			Time:    3 * time.Minute,
			Timeout: 20 * time.Second,
		}),
	}
}

func Setup(params *SetupRequest, platformInterface libbox.PlatformInterface) error {
	defer config.DeferPanicToError("setup", func(err error) {
		Log(LogLevel_FATAL, LogType_CORE, err.Error())
		<-time.After(5 * time.Second)
	})
	if params.Debug {
		go func() {
			http.ListenAndServe("localhost:6060", nil)
		}()
	}
	mu.Lock()
	defer mu.Unlock()
	// Register this mode's platform BEFORE the early return below: a re-Setup
	// over a live server (Android bg start after an fg setup, resume flows) must
	// still (re-)resolve the shared platform, or the next box start keeps a
	// stale/downgraded interface. Never downgrades to nil (v4.3.9 netlink fix);
	// background modes win over foreground (resolvePlatformLocked).
	static.setPlatformForMode(params.Mode, platformInterface)
	if grpcServer[params.Mode] != nil {
		// Server already serving: refresh the shared context/TestEngine deps so
		// later box starts see the re-resolved platform, then no-op.
		if static.baseContext() != nil {
			static.setBaseContext(libbox.BaseContext(static.platform()))
			configureTestEngine()
		}
		Log(LogLevel_WARNING, LogType_CORE, "grpcServer already started")
		return nil
	}
	static.debug = params.Debug
	tcpConn := true // runtime.GOOS == "windows" // TODO add TVOS
	libbox.Setup(
		&libbox.SetupOptions{
			BasePath:          params.BasePath,
			WorkingPath:       params.WorkingDir,
			TempPath:          params.TempDir,
			// IsTVOS:          !tcpConn,
			FixAndroidStack:   params.FixAndroidStack,
			LogMaxLines:       100,
			Debug:             params.Debug,
			// OOM fields are applied per-Start via configureMemoryLimit (DisableMemoryLimit).
			OomKillerEnabled:  false,
			OomKillerDisabled: true,
			OomMemoryLimit:    0,
		})

	// BaseContext must be built AFTER libbox.Setup so filemanager gets real
	// working/temp paths and uid/gid. Creating it earlier leaves chown=true with
	// uid 0 on Windows (Getuid()==-1) → "chown ... not supported by windows".
	static.setBaseContext(libbox.BaseContext(static.platform()))

	// Setup() already pointed crash output at CrashReport-*.log; override with a
	// mode-specific path under data/ (uses LX libbox.RedirectStderr + archive).
	_ = libbox.RedirectStderr(fmt.Sprint(params.WorkingDir, "/data/stderr", params.Mode, ".log"))

	Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf("libbox.Setup success %s %s %s %v", params.BasePath, params.WorkingDir, params.TempDir, tcpConn))

	sWorkingPath = params.WorkingDir
	os.Chdir(sWorkingPath)
	sTempPath = params.TempDir
	sUserID = os.Getuid()
	sGroupID = os.Getgid()
	configureTestEngine()

	var defaultWriter io.Writer
	if !params.Debug {
		defaultWriter = io.Discard
	}
	factory, err := log.New(
		log.Options{
			DefaultWriter: defaultWriter,
			BaseTime:      time.Now(),
			Observable:    true,
			// Options: option.LogOptions{
			// 	Disabled: false,
			// 	Level:    "trace",
			// 	Output:   "stdout",
			// },
		})
	static.CoreLogFactory = factory

	if err != nil {
		return E.Cause(err, "create logger")
	}

	Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf("StartGrpcServerByMode %s %d\n", params.Listen, params.Mode))
	switch params.Mode {
	case SetupMode_OLD:
		statusPropagationPort = int64(params.FlutterStatusPort)
	// case SetupMode_GRPC_BACKGROUND_INSECURE:
	default:
		_, err := StartGrpcServerByMode(params.Listen, params.Mode)
		if err != nil {
			return err
		}
	}
	settings := db.GetTable[hcommon.AppSettings]()
	val, err := settings.Get("ClientSettingsJson")
	Log(LogLevel_DEBUG, LogType_CORE, "ClientSettingsJson", val, err)
	if val == nil || err != nil {
		// if params.Mode == SetupMode_GRPC_BACKGROUND_INSECURE {
		_, err := ChangeClientSettings(&ChangeClientSettingsRequest{ClientSettingsJson: ""}, false)
		if err != nil {
			Log(LogLevel_ERROR, LogType_CORE, E.Cause(err, "ChangeClientSettings").Error())
		}
	} else {
		// settings := db.GetTable[hcommon.AppSettings]()
		_, err := ChangeClientSettings(&ChangeClientSettingsRequest{ClientSettingsJson: val.Value.(string)}, false)
		if err != nil {
			Log(LogLevel_ERROR, LogType_CORE, E.Cause(err, "ChangeClientSettings").Error())
		}

	}
	hutils.HealStickyTun()
	SessionInit(params.WorkingDir)
	return InitPathologyService()
}

func StartGrpcServer(listenAddressG string, service string) (*grpc.Server, error) {
	lis, err := net.Listen("tcp", listenAddressG)
	if err != nil {
		log.Error("failed to listen: %v", err)
		return nil, err
	}
	s := grpc.NewServer(append(grpcKeepaliveOptions(), grpcRecoveryOptions()...)...)
	if service == "core" {
		// Setup("./tmp/", "./tmp", "./tmp", 11111, false)
		RegisterCoreServer(s, &CoreService{})
		// pb.RegisterExtensionHostServiceServer(s, &extension.ExtensionHostService{})
	} else if service == "hello" {
		// RegisterHelloServer(s, &hello.HelloService{})
	} else if service == "ezytel" {
		ezytel.RegisterEzytelServer(s, ezytel.NewEzytelService(ezytelCacheDir()))
	} else if service == "tunnel" {
		// RegisterTunnelServiceServer(s, &TunnelService{})
	}
	log.Info("Server listening on %s", listenAddressG)
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Error("failed to serve: %v", err)
		}
		log.Info("Server stopped")
		// cancel()
	}()
	return s, nil
}

func StartCoreGrpcServer(listenAddressG string) (*grpc.Server, error) {
	return StartGrpcServer(listenAddressG, "core")
}

func StartHelloGrpcServer(listenAddressG string) (*grpc.Server, error) {
	return StartGrpcServer(listenAddressG, "hello")
}

var (
	certpair   *hutils.CertificatePair
	grpcServer map[SetupMode]*grpc.Server = make(map[SetupMode]*grpc.Server)
	caCertPool                            = x509.NewCertPool()
	mu                                    = sync.Mutex{}
)

// StartGrpcServerByMode starts a gRPC server on the specified address with mTLS.
func StartGrpcServerByMode(listenAddressG string, mode SetupMode) (*grpc.Server, error) {
	// Validate the listen address
	if !strings.Contains(listenAddressG, ":") {
		return nil, fmt.Errorf("invalid listen address (no port): %s", listenAddressG)
	}
	// Convert the port from string to uint16
	portStr := strings.Split(listenAddressG, ":")[1]
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to convert port %s to uint16: %v", portStr, err)
	}
	if hutils.IsPortInUse(uint16(port)) {
		return nil, fmt.Errorf("port %s is already in use", portStr)
	}
	// Fetch the server private key and public key from the database
	if _, exists := grpcServer[mode]; exists {
		Log(LogLevel_WARNING, LogType_CORE, "grpcServer already started")
		return grpcServer[mode], nil
	}

	if mode == SetupMode_GRPC_BACKGROUND_INSECURE || mode == SetupMode_GRPC_NORMAL_INSECURE {
		grpcServer[mode] = grpc.NewServer(append(grpcKeepaliveOptions(), grpcRecoveryOptions()...)...)
	} else {
		table := db.GetTable[hcommon.AppSettings]()
		Log(LogLevel_DEBUG, LogType_CORE, table)
		grpcServerPrivateKey, err := table.Get("grpc_server_private_key")
		grpcServerPublicKey, err2 := table.Get("grpc_server_public_key")
		if err != nil || err2 != nil {
			Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf("failed to get grpc_server_private_key and grpc_server_public_key from database: %v %v\n", err, err2))
			certpair, err = hutils.GenerateCertificatePair()
			if err != nil {
				Log(LogLevel_ERROR, LogType_CORE, fmt.Sprintf("failed to generate certificate pair: %v", err))

				return nil, err
			}
			table.UpdateInsert(
				&hcommon.AppSettings{Id: "grpc_server_public_key", Value: certpair.Certificate},
				&hcommon.AppSettings{Id: "grpc_server_private_key", Value: certpair.PrivateKey},
			)
		} else {
			certpair = &hutils.CertificatePair{
				Certificate: grpcServerPublicKey.Value.([]byte),
				PrivateKey:  grpcServerPrivateKey.Value.([]byte),
			}
		}
		// Load server certificate and private key
		serverCert, err := tls.X509KeyPair(certpair.Certificate, certpair.PrivateKey)
		if err != nil {
			Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf("failed to load server certificate and key: %v\n", err))

			return nil, err
		}

		// Create TLS credentials for the gRPC server
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert, // Enforce mutual TLS (mTLS)
			ClientCAs:    caCertPool,                     // Client CAs to verify client certificates
		}

		// Create a new gRPC server with TLS credentials
		creds := credentials.NewTLS(tlsConfig)
		mtlsOpts := append(grpcKeepaliveOptions(), grpcRecoveryOptions()...)
		grpcServer[mode] = grpc.NewServer(append(mtlsOpts, grpc.Creds(creds))...)
	}
	// Register your gRPC service here
	RegisterCoreServer(grpcServer[mode], &CoreService{})
	hello.RegisterHelloServer(grpcServer[mode], &hello.HelloService{})
	ezytel.RegisterEzytelServer(grpcServer[mode], ezytel.NewEzytelService(ezytelCacheDir()))
	// Listen on the provided address
	lis, err := net.Listen("tcp", listenAddressG)
	if err != nil {
		Log(LogLevel_ERROR, LogType_CORE, fmt.Sprintf("failed to listen on %s: %v\n", listenAddressG, err))
		return nil, err
	}
	Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf("grpcServer started on %s\n", listenAddressG))
	log.Info("Server listening on %s", listenAddressG)

	// Run the server in a goroutine. Capture the instance: reading
	// grpcServer[mode] here raced with Close (unsynchronized map read), and a
	// Serve that dies on its own left a zombie map entry — every later Setup
	// short-circuited on "already started" while nothing was listening
	// (connection-refused until process restart). Clean the entry on exit so
	// the next Setup rebinds.
	srv := grpcServer[mode]
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logRecoveredPanic(fmt.Sprintf("grpc.Serve(mode=%d)", mode), r)
			}
			mu.Lock()
			if cur, ok := grpcServer[mode]; ok && cur == srv {
				delete(grpcServer, mode)
				Log(LogLevel_WARNING, LogType_CORE, fmt.Sprintf("grpc serve exited; cleared mode %d so Setup can rebind", mode))
			}
			mu.Unlock()
		}()
		if err := srv.Serve(lis); err != nil {
			Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf("failed to serve: %v\n", err))
		}
		Log(LogLevel_DEBUG, LogType_CORE, "Server stopped")
	}()

	return grpcServer[mode], nil
}

// GetGrpcServerPublicKey returns the gRPC server's public key.
// Nil-safe: certpair is only generated in the mTLS modes — Android/desktop
// run the insecure modes, and a nil deref here would abort the whole app
// process (c-shared/JNI export path via Mobile.getServerPublicKey).
func GetGrpcServerPublicKey() []byte {
	if certpair == nil {
		return nil
	}
	return certpair.Certificate
}

// hasGrpcServer reports whether mode's server is registered (mu-guarded —
// Setup/Close mutate the map; bare reads from RPC handlers race with them and
// can trigger "concurrent map read and map write" = unrecoverable throw).
func hasGrpcServer(mode SetupMode) bool {
	mu.Lock()
	defer mu.Unlock()
	return grpcServer[mode] != nil
}

// AddGrpcClientPublicKey adds a client's public key to the CA pool for verification.
func AddGrpcClientPublicKey(clientPublicKey []byte) error {
	block, _ := pem.Decode(clientPublicKey)
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("failed to decode client public key")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse client public key: %v", err)
		}
		cert = &x509.Certificate{
			PublicKey: pubKey,
		}
	}
	caCertPool.AddCert(cert)

	return nil
}

func CloseGrpcServer(mode SetupMode) {
	mu.Lock()
	defer mu.Unlock()
	if server, ok := grpcServer[mode]; ok && server != nil {
		server.Stop()
		delete(grpcServer, mode)
	}
	// The closed mode's platform no longer represents a live service: re-resolve
	// the shared interface (e.g. bg VPNService wrapper gone → fg wrapper takes
	// over) and refresh BaseContext/TestEngine deps so the next box start on the
	// surviving mode does not keep a destroyed Kotlin service as its platform.
	static.dropPlatformForMode(mode)
	if static.baseContext() != nil {
		static.setBaseContext(libbox.BaseContext(static.platform()))
		configureTestEngine()
	}
}

// anyGrpcServerAlive reports whether any mode's gRPC server is still serving.
// Android runs the fg and bg modes in ONE process: the shared LevelDB must
// stay open while any mode can still receive RPCs — db.CloseAll under a live
// server panics the next RPC goroutine and takes the whole process down.
func anyGrpcServerAlive() bool {
	mu.Lock()
	defer mu.Unlock()
	for _, s := range grpcServer {
		if s != nil {
			return true
		}
	}
	return false
}

// ezytelCacheDir keeps ezytel under Setup TempDir (portable_data/tmp) instead of os.TempDir.
func ezytelCacheDir() string {
	if sTempPath != "" {
		return filepath.Join(sTempPath, "ezytel-cache")
	}
	return filepath.Join(os.TempDir(), "ezytel-cache")
}
