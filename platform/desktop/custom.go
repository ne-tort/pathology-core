package main

/*
#include <stdlib.h>
#include <signal.h>
#include "stdint.h"
*/
import "C"

import (
	// "os"
	// "os/signal"

	"runtime"

	// "syscall"
	"unsafe"

	hcore "github.com/ne-tort/pathology-core/v2/hcore"
	coretray "github.com/ne-tort/pathology-core/v2/hcore/tray"
	hutils "github.com/ne-tort/pathology-core/v2/hutils"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
)

// func init() {
// 	runtime.LockOSThread()
// 	C.init_signals()
// 	runtime.UnlockOSThread()

// 	go handleSignals()

// 	// Your other initialization code can go here
// }

// // Signal handling function
// func handleSignals() {
// 	signalChan := make(chan os.Signal, 1)
// 	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGURG)

// 	for {
// 		<-signalChan
// 		// switch sig {
// 		// case syscall.SIGINT, syscall.SIGTERM:
// 		// 	// runtime.LockOSThread() // Lock to the current OS thread
// 		// 	// defer runtime.UnlockOSThread()
// 		// 	log.Info("Received signal:", sig)

// 		// 	// Call stop function or perform cleanup
// 		// 	if err := stop(); err != nil {
// 		// 		log.Error("Error stopping the application:", err)
// 		// 	}
// 		// 	log.Info("Application stopped gracefully.")
// 		// }
// 	}
// }

func main() {}

//export cleanup
func cleanup() {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()
	// C.cleanup_signals()
}

func emptyOrErrorC(err error) *C.char {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err == nil {
		return C.CString("")
	}
	log.Error(err.Error())
	str := C.CString(err.Error())
	defer C.free(unsafe.Pointer(str))
	return str
}

//export setup
func setup(baseDir *C.char, workingDir *C.char, tempDir *C.char, mode C.int, listen *C.char, secret *C.char, statusPort C.longlong, debug bool) (ret *C.char) {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	// // Ensure signals are initialized
	// C.init_signals()

	// In-process DLL: an unrecovered panic here aborts the whole UI process.
	var err error
	defer func() {
		hcore.RecoverExportErr("desktop.setup", &err)
		if err != nil && ret == nil {
			ret = emptyOrErrorC(err)
		}
	}()

	params := hcore.SetupRequest{
		BasePath:          C.GoString(baseDir),
		WorkingDir:        C.GoString(workingDir),
		TempDir:           C.GoString(tempDir),
		FlutterStatusPort: int64(statusPort),
		Debug:             bool(debug),
		Mode:              hcore.SetupMode(mode),
		Listen:            C.GoString(listen),
		Secret:            C.GoString(secret),
	}

	err = hcore.Setup(&params, nil)
	return emptyOrErrorC(err)
}

//export freeString
func freeString(str *C.char) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	C.free(unsafe.Pointer(str))
}

//export start
func start(configPath *C.char, disableMemoryLimit bool) (ret *C.char) {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()
	var err error
	defer func() {
		hcore.RecoverExportErr("desktop.start", &err)
		if err != nil && ret == nil {
			ret = emptyOrErrorC(err)
		}
	}()
	ctx := libbox.BaseContext(nil)
	_, err = hcore.Start(ctx, &hcore.StartRequest{
		ConfigPath:             C.GoString(configPath),
		EnableOldCommandServer: true,
		DisableMemoryLimit:     bool(disableMemoryLimit),
	})
	return emptyOrErrorC(err)
}

//export stop
func stop() (ret *C.char) {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	var err error
	defer func() {
		hcore.RecoverExportErr("desktop.stop", &err)
		if err != nil && ret == nil {
			ret = emptyOrErrorC(err)
		}
	}()
	_, err = hcore.Stop()
	return emptyOrErrorC(err)
}

//export healStickyTun
func healStickyTun() {
	defer hcore.RecoverExport("desktop.healStickyTun")
	hutils.HealStickyTun()
}

//export restart
func restart(configPath *C.char, disableMemoryLimit bool) (ret *C.char) {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()
	var err error
	defer func() {
		hcore.RecoverExportErr("desktop.restart", &err)
		if err != nil && ret == nil {
			ret = emptyOrErrorC(err)
		}
	}()
	ctx := libbox.BaseContext(nil)
	_, err = hcore.Restart(ctx, &hcore.StartRequest{
		ConfigPath:             C.GoString(configPath),
		EnableOldCommandServer: true,
		DisableMemoryLimit:     bool(disableMemoryLimit),
	})
	return emptyOrErrorC(err)
}

//export GetServerPublicKey
func GetServerPublicKey() (ret *C.char) {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	// In-process DLL: an unrecovered panic here aborts the whole UI process.
	defer func() {
		var err error
		hcore.RecoverExportErr("desktop.getServerPublicKey", &err)
		if err != nil && ret == nil {
			ret = emptyOrErrorC(err)
		}
	}()

	publicKey := hcore.GetGrpcServerPublicKey()
	return C.CString(string(publicKey)) // Return as C string, caller must free
}

//export AddGrpcClientPublicKey
func AddGrpcClientPublicKey(clientPublicKey *C.char) (ret *C.char) {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	// In-process DLL: an unrecovered panic here aborts the whole UI process.
	var err error
	defer func() {
		hcore.RecoverExportErr("desktop.addGrpcClientPublicKey", &err)
		if err != nil && ret == nil {
			ret = emptyOrErrorC(err)
		}
	}()

	// Convert C string to Go byte slice
	clientKey := C.GoBytes(unsafe.Pointer(clientPublicKey), C.int(len(C.GoString(clientPublicKey))))
	err = hcore.AddGrpcClientPublicKey(clientKey)
	return emptyOrErrorC(err)
}

//export startTray
func startTray(uiExe *C.char, basePath *C.char, lang *C.char) (ret *C.char) {
	defer func() {
		var err error
		hcore.RecoverExportErr("desktop.startTray", &err)
		if err != nil && ret == nil {
			ret = emptyOrErrorC(err)
		}
	}()
	coretray.StartTray(coretray.Options{
		UIExe:       C.GoString(uiExe),
		BasePath:    C.GoString(basePath),
		Lang:        C.GoString(lang),
		UiLifecycle: coretray.UiLifecycleEmbedded,
	})
	return emptyOrErrorC(nil)
}

//export closeGrpc
func closeGrpc(mode C.int) {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	defer hcore.RecoverExport("desktop.closeGrpc")
	hcore.Close(hcore.SetupMode(mode))
}
