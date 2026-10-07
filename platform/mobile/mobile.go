package mobile

import (
	hcore "github.com/ne-tort/pathology-core/v2/hcore"

	_ "net/http/pprof"

	_ "github.com/sagernet/gomobile"
	"github.com/sagernet/sing-box/experimental/libbox"
)

// Every function in this package crosses the gomobile/JNI boundary on Android,
// where the core shares ONE process with the Flutter UI: a panic that unwinds
// into the generated binding aborts the whole app. Each export therefore starts
// with a recover (hcore.RecoverExport*) so a core fault degrades to an error /
// no-op with the stack captured in stderr*.log instead of killing the client.

type SetupOptions struct {
	BasePath         string
	WorkingDir       string
	TempDir          string
	Listen           string
	Secret           string
	Debug            bool
	Mode             int
	FixAndroidStack  bool
	OomKillerEnabled bool
}

func Setup(opt *SetupOptions, platformInterface libbox.PlatformInterface) (err error) {
	defer hcore.RecoverExportErr("Setup", &err)
	if err = hcore.Setup(&hcore.SetupRequest{
		BasePath:          opt.BasePath,
		WorkingDir:        opt.WorkingDir,
		TempDir:           opt.TempDir,
		FlutterStatusPort: 0,
		Listen:            opt.Listen,
		Debug:             opt.Debug,
		Mode:              hcore.SetupMode(opt.Mode),
		Secret:            opt.Secret,
		FixAndroidStack:   opt.FixAndroidStack,
	}, platformInterface); err != nil {
		return err
	}
	// libbox SetMemoryLimit was removed; OOM policy is applied via SetupOptions.
	libbox.ReloadSetupOptions(&libbox.SetupOptions{
		OomKillerEnabled:  opt.OomKillerEnabled,
		OomKillerDisabled: !opt.OomKillerEnabled,
	})
	return nil
}

// func Start(configPath string, configContent string, platformInterface libbox.PlatformInterface) (*hcore.CoreInfoResponse, error) {
// 	state, err := hcore.StartWithPlatformInterface(&hcore.StartRequest{
// 		ConfigContent: configContent,
// 		ConfigPath:    configPath,
// 	}, platformInterface)
// 	return state, err
// }

func Start(configPath string, configContent string) (err error) {
	defer hcore.RecoverExportErr("Start", &err)
	_, err = hcore.StartService(libbox.BaseContext(nil), &hcore.StartRequest{
		ConfigPath:    configPath,
		ConfigContent: configContent,
	})
	return err
}

func Stop() (err error) {
	defer hcore.RecoverExportErr("Stop", &err)
	_, err = hcore.Stop()
	return err
}

func GetServerPublicKey() (out []byte) {
	defer hcore.RecoverExport("GetServerPublicKey")
	return hcore.GetGrpcServerPublicKey()
}

func AddGrpcClientPublicKey(clientPublicKey []byte) (err error) {
	defer hcore.RecoverExportErr("AddGrpcClientPublicKey", &err)
	return hcore.AddGrpcClientPublicKey(clientPublicKey)
}

func Close(mode int) {
	defer hcore.RecoverExport("Close")
	hcore.Close(hcore.SetupMode(mode))
}

func Test() string {
	return "Hello from mobile"
}

func Pause() {
	defer hcore.RecoverExport("Pause")
	hcore.Pause()
}

func Wake() {
	defer hcore.RecoverExport("Wake")
	hcore.Wake()
}

func ResetNetwork() {
	defer hcore.RecoverExport("ResetNetwork")
	hcore.ResetNetwork()
}
