package hcore

import (
	"fmt"
)

// RecoverExport contains a panic inside a cgo/gomobile-exported function.
//
// On Android (and on desktop in-process DLL mode) the core shares ONE process
// with the Flutter UI: a panic that unwinds across the JNI/FFI boundary aborts
// the whole app (SIGABRT), and platform callers (Kotlin DefaultNetworkMonitor,
// Dart FFI) invoke exports directly from foreign threads. Recovering at the
// export boundary keeps the failure contained; the stack lands in the
// redirected stderr (stderr*.log / crash_reports) and the core log stream.
//
// op is the full dotted label, e.g. "mobile.Setup" or "desktop.setup".
func RecoverExport(op string) {
	if r := recover(); r != nil {
		logRecoveredPanic(op, r)
	}
}

// RecoverExportErr is RecoverExport for exports with an error return: the
// recovered panic is reported to the caller as an error instead of silence.
func RecoverExportErr(op string, err *error) {
	if r := recover(); r != nil {
		logRecoveredPanic(op, r)
		if err != nil {
			*err = fmt.Errorf("core panic in %s: %v", op, r)
		}
	}
}
