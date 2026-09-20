//go:build windows || darwin || linux

package tray

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	hcore "github.com/ne-tort/pathology-core/v2/hcore"
	"github.com/ne-tort/pathology-core/v2/hcore/session"

	"fyne.io/systray"
)

// Options configures the unified core-owned system tray.
type Options struct {
	UIExe       string
	BasePath    string
	Lang        string
	UiLifecycle UiLifecycle
}

var (
	startOnce sync.Once
	doneCh    chan struct{}
	doneOnce  sync.Once

	uiExe        string
	basePath     string
	uiLifecycle  UiLifecycle
	fallbackLang = "en"
	locale       localeStrings
	darkMenu     bool
	themeMode    = "system"

	menuMu           sync.Mutex
	showItem         *systray.MenuItem
	quitItem         *systray.MenuItem
	toggleItem       *systray.MenuItem
	reconnectItem    *systray.MenuItem
	profilesMenu     *systray.MenuItem
	serviceModeMenu  *systray.MenuItem
	modeProxyItem    *systray.MenuItem
	modeSysProxyItem *systray.MenuItem
	modeTunItem      *systray.MenuItem
	profileSubItems  []*systray.MenuItem
	lastProfilesHash string
)

func initLabels(p prefs) {
	locale = labelsForLocale(p.Locale)
	themeMode = p.ThemeMode
	darkMenu = resolveDarkMenu(p)
}

func resolveDarkMenu(p prefs) bool {
	switch p.ThemeMode {
	case "dark", "black":
		return true
	case "system":
		return osPrefersDarkMenu()
	default:
		return false
	}
}

// StartTray starts the core-owned tray icon (idempotent).
func StartTray(opts Options) {
	startOnce.Do(func() {
		doneCh = make(chan struct{})
		uiExe = opts.UIExe
		if uiExe == "" {
			uiExe = defaultUIExePath()
		}
		basePath = opts.BasePath
		uiLifecycle = opts.UiLifecycle
		if opts.Lang != "" {
			fallbackLang = opts.Lang
		}
		initialPrefs := loadPrefs(basePath, fallbackLang)
		initLabels(initialPrefs)
		// Apply dark/light chrome before systray.Run so the native popup menu and
		// tray window pick up the correct immersive theme on creation.
		initTheme(themeMode)
		registerDisplaySyncHandler()
		setupClickHandlers(onTrayClick)
		// Tray goroutine owns the systray lifecycle. LockOSThread pins the Win32
		// message loop (GetMessage/DispatchMessage → WndProc) to one OS thread,
		// which Win32 message-only windows require. runDispatcher serializes all
		// menu/icon mutations on a single goroutine so concurrent refresh requests
		// from gRPC/prefs/transition pollers can't race with each other or with
		// systrayMenuItemSelected inside WndProc.
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ctx, cancel := context.WithCancel(context.Background())
			trayCtx = ctx
			go runDispatcher(ctx.Done())
			defer cancel()
			systray.Run(onReady, onExit)
		}()
	})
}

func Done() <-chan struct{}  { return doneCh }
func StopTray()              { systray.Quit() }

func SpawnUIReconnect() {
	requestUiShowOrSpawn()
}

func onReady() {
	initTheme(themeMode)
	applyDarkContextMenu()
	systray.SetTitle("Pathology")
	systray.SetTooltip("Pathology")
	applyTrayIcon(hcore.CurrentCoreState(), darkMenu)

	startPrefsWatcher(trayCtx, basePath)

	showItem = systray.AddMenuItem(locale.ShowWindow, "")
	systray.AddSeparator()
	toggleItem = systray.AddMenuItem(locale.Connect, "")
	reconnectItem = systray.AddMenuItem(locale.Reconnect, "")
	profilesMenu = systray.AddMenuItem(locale.Profiles, "")
	serviceModeMenu = systray.AddMenuItem(locale.ServiceMode, "")
	modeProxyItem = serviceModeMenu.AddSubMenuItemCheckbox(locale.ModeProxy, "", false)
	modeSysProxyItem = serviceModeMenu.AddSubMenuItemCheckbox(locale.ModeSystemProxy, "", false)
	modeTunItem = serviceModeMenu.AddSubMenuItemCheckbox(locale.ModeTun, "", false)
	systray.AddSeparator()
	quitItem = systray.AddMenuItem(locale.Quit, "")

	refreshTrayDisplay()

	go func() {
		for {
			select {
			case <-showItem.ClickedCh:
				SpawnUIReconnect()
			case <-toggleItem.ClickedCh:
				if toggleItem.Disabled() {
					continue
				}
				if connectionMenuFor(hcore.CurrentCoreState(), locale).isConnected {
					handleSession(hcore.SessionDisconnect)
				} else {
					handleSession(hcore.SessionConnect)
				}
			case <-reconnectItem.ClickedCh:
				handleSession(hcore.SessionReconnect)
			case <-modeProxyItem.ClickedCh:
				handleSetServiceMode("proxy")
			case <-modeSysProxyItem.ClickedCh:
				handleSetServiceMode("system-proxy")
			case <-modeTunItem.ClickedCh:
				handleSetServiceMode("vpn")
			case <-quitItem.ClickedCh:
				if pid, alive := resolveUiPid(); alive {
					requestUiQuit(pid)
				}
				_, _ = hcore.SessionDisconnect(context.Background())
				systray.Quit()
				return
			}
		}
	}()
}

func refreshTrayDisplay() {
	dispatch(func() {
		p := loadPrefs(basePath, fallbackLang)
		initLabels(p)
		initTheme(themeMode)
		applyDarkContextMenu()
		refreshAllMenuLabels()
		rebuildProfileSubmenuIfNeeded()
		rebuildServiceModeChecksFrom(hcore.SessionGetState().ServiceMode)
		refreshConnectionUISync(hcore.CurrentCoreState())
	})
}

func handleSession(fn func(context.Context) (*hcore.CoreInfoResponse, error)) {
	resp, err := fn(context.Background())
	state := hcore.CurrentCoreState()
	if msg := hcore.SessionLastErrorMessage(resp, err); msg != "" {
		systray.SetTooltip("Pathology — " + msg)
	}
	refreshConnectionUI(state)
	if state == hcore.CoreStates_STARTING || state == hcore.CoreStates_STOPPING {
		watchCoreTransitions(trayCtx)
	}
}

func handleSetServiceMode(mode string) {
	st, err := hcore.SessionSetServiceMode(mode)
	if err != nil {
		systray.SetTooltip("Pathology — " + err.Error())
		return
	}
	dispatch(func() { rebuildServiceModeChecksFrom(st.ServiceMode) })
	if hcore.CurrentCoreState() == hcore.CoreStates_STARTED {
		handleSession(hcore.SessionReconnect)
	}
}

func refreshAllMenuLabels() {
	menuMu.Lock()
	defer menuMu.Unlock()
	if showItem != nil {
		showItem.SetTitle(locale.ShowWindow)
	}
	if quitItem != nil {
		quitItem.SetTitle(locale.Quit)
	}
	if profilesMenu != nil {
		profilesMenu.SetTitle(locale.Profiles)
	}
	if serviceModeMenu != nil {
		serviceModeMenu.SetTitle(locale.ServiceMode)
	}
	if modeProxyItem != nil {
		modeProxyItem.SetTitle(locale.ModeProxy)
	}
	if modeSysProxyItem != nil {
		modeSysProxyItem.SetTitle(locale.ModeSystemProxy)
	}
	if modeTunItem != nil {
		modeTunItem.SetTitle(locale.ModeTun)
	}
	if reconnectItem != nil {
		reconnectItem.SetTitle(locale.Reconnect)
	}
}

func refreshConnectionMenu(state hcore.CoreStates) {
	menuMu.Lock()
	defer menuMu.Unlock()
	if toggleItem == nil {
		return
	}
	m := connectionMenuFor(state, locale)
	toggleItem.SetTitle(m.toggleLabel)
	if m.toggleEnabled {
		toggleItem.Enable()
	} else {
		toggleItem.Disable()
	}
	if m.showReconnect {
		reconnectItem.Show()
		reconnectItem.Enable()
	} else {
		reconnectItem.Hide()
	}
}

func profilesHash(st session.State) string {
	h := sha256.New()
	for _, p := range st.Profiles {
		h.Write([]byte(p.ID))
		h.Write([]byte(p.Name))
		if p.Active {
			h.Write([]byte{1})
		}
	}
	for _, id := range st.ActiveProfileIDs {
		h.Write([]byte(id))
	}
	if st.DirectMode {
		h.Write([]byte("direct"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func rebuildProfileSubmenuIfNeeded() {
	st := hcore.SessionGetState()
	hash := profilesHash(st)
	if hash == lastProfilesHash {
		return
	}
	lastProfilesHash = hash

	menuMu.Lock()
	defer menuMu.Unlock()
	if profilesMenu == nil {
		return
	}
	for _, item := range profileSubItems {
		item.Remove()
	}
	profileSubItems = profileSubItems[:0]

	if len(st.Profiles) == 0 {
		placeholder := profilesMenu.AddSubMenuItem("—", "")
		placeholder.Disable()
		profileSubItems = append(profileSubItems, placeholder)
		return
	}
	for _, p := range st.Profiles {
		item := profilesMenu.AddSubMenuItemCheckbox(p.Name, "", p.Active)
		profileSubItems = append(profileSubItems, item)
		id := p.ID
		go func(it *systray.MenuItem, profileID string) {
			for range it.ClickedCh {
				if _, err := session.SetActiveProfiles([]string{profileID}); err != nil {
					systray.SetTooltip("Pathology — " + err.Error())
					continue
				}
				lastProfilesHash = ""
				if hcore.CurrentCoreState() == hcore.CoreStates_STARTED {
					handleSession(hcore.SessionReconnect)
				}
			}
		}(item, id)
	}
}

func rebuildServiceModeChecksFrom(mode string) {
	menuMu.Lock()
	defer menuMu.Unlock()
	if modeProxyItem == nil {
		return
	}
	if mode == "proxy" || mode == "" {
		modeProxyItem.Check()
	} else {
		modeProxyItem.Uncheck()
	}
	if mode == "system-proxy" {
		modeSysProxyItem.Check()
	} else {
		modeSysProxyItem.Uncheck()
	}
	if mode == "vpn" {
		modeTunItem.Check()
	} else {
		modeTunItem.Uncheck()
	}
}

func onExit() {
	doneOnce.Do(func() {
		if doneCh != nil {
			close(doneCh)
		}
	})
	// Drain pending commands so queued refreshes after Quit don't touch a
	// torn-down systray; isReady guards the actual Win32 calls anyway.
	for {
		select {
		case fn, ok := <-cmdCh:
			if !ok {
				return
			}
			fn()
		default:
			return
		}
	}
}

func defaultUIExePath() string {
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(self)
	if runtime.GOOS == "windows" {
		return filepath.Join(dir, "Pathology.exe")
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(dir, "Pathology.app", "Contents", "MacOS", "Pathology")
	}
	return filepath.Join(dir, "pathology")
}
