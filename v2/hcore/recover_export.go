package hcore

import (
	"fmt"
)

// RecoverExport contains a panic inside a cgo/gomobile-exported function.
//
// On Android the core shares ONE process with the Flutter UI: a panic that
// unwinds across the JNI boundary aborts the whole app (SIGABRT), and Kotlin
// callers such as DefaultNetworkMonitor call Mobile.wake/resetNetwork directly
// from JVM threads. Recovering at the export boundary keeps the failure
// contained; the stack lands in the redirected stderr (stderr*.log /
// crash_reports) and the core log stream.
func RecoverExport(op string) {
	if r := recover(); r != nil {
		logRecoveredPanic("mobile."+op, r)
	}
}

// RecoverExportErr is RecoverExport for exports with an error return: the
// recovered panic is reported to the caller as an error instead of silence.
func RecoverExportErr(op string, err *error) {
	if r := recover(); r != nil {
		logRecoveredPanic("mobile."+op, r)
		if err != nil {
			*err = fmt.Errorf("core panic in mobile.%s: %v", op, r)
		}
	}
}
