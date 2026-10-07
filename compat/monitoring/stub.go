// Package monitoring runs URL tests against live outbounds and mirrors
// results into sing-box HistoryStorage so proxy streams see delay updates.
package monitoring

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing/common/batch"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/observable"
)

// FailDelay is stored when a probe fails or exceeds MaxSuccessDelay.
const FailDelay uint16 = 65535

// MaxSuccessDelay: anything slower is treated as a failed probe.
const MaxSuccessDelay uint16 = 3000

// DefaultProbeTimeout bounds a single URL test when the client omits a timeout.
const DefaultProbeTimeout = 3 * time.Second

// ProbeTimeout is kept as an alias for callers that still reference the old name.
const ProbeTimeout = DefaultProbeTimeout

// deactivateWaitBudget: cancel probes on Stop, then wait before CloseService
// (covers fastAverage; stress may still time out — better than hanging Disconnect).
const deactivateWaitBudget = 15 * time.Second

// GroupEvent is emitted when URL-test history changes.
type GroupEvent struct{}

// OutboundMonitoring runs URL tests against live outbounds and mirrors
// results into sing-box HistoryStorage so proxy streams see delay updates.
type OutboundMonitoring struct {
	ctx      context.Context
	cancel   context.CancelFunc
	box      *box.Box
	history  *urltest.HistoryStorage
	testURLs func() []string
	strategy func() string
	timeout  func() time.Duration
	events   *Broadcaster[GroupEvent]
	hook     *observable.Subscriber[struct{}]

	probesInFlight sync.WaitGroup
}

var active atomic.Pointer[OutboundMonitoring]

// Activate binds monitoring to the running core instance.
// testURLs returns the selected probe endpoints (empty → skip).
// strategy is single | fastAverage | stress (sample counts 1/3/10).
// timeout bounds each URL probe attempt (nil → DefaultProbeTimeout).
func Activate(ctx context.Context, b *box.Box, history *urltest.HistoryStorage, testURLs func() []string, strategy func() string, timeout func() time.Duration) {
	if ctx == nil || b == nil || history == nil {
		return
	}
	if testURLs == nil {
		testURLs = func() []string { return nil }
	}
	if strategy == nil {
		strategy = func() string { return "single" }
	}
	if timeout == nil {
		timeout = func() time.Duration { return DefaultProbeTimeout }
	}

	Deactivate()

	probeCtx, cancel := context.WithCancel(ctx)
	m := &OutboundMonitoring{
		ctx:      probeCtx,
		cancel:   cancel,
		box:      b,
		history:  history,
		testURLs: testURLs,
		strategy: strategy,
		timeout:  timeout,
		events:   NewBroadcaster[GroupEvent](probeCtx),
		hook:     observable.NewSubscriber[struct{}](4),
	}
	history.AddUpdateHook(m.hook)
	go m.relayHistoryUpdates()
	active.Store(m)
}

func (m *OutboundMonitoring) probeTimeout() time.Duration {
	if m != nil && m.timeout != nil {
		if d := m.timeout(); d > 0 {
			return d
		}
	}
	return DefaultProbeTimeout
}

// Deactivate drops the active monitor (service stop / reload).
// Cancels in-flight probes and waits briefly so Disconnect does not Close
// the box under live Reality/XHTTP dials (Connect analogue of TestEngine H-N6).
func Deactivate() {
	if m := active.Swap(nil); m != nil {
		if m.cancel != nil {
			m.cancel()
		}
		done := make(chan struct{})
		go func() {
			m.probesInFlight.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(deactivateWaitBudget):
			log.Printf("monitoring: wait for in-flight urltest probes timed out after %v", deactivateWaitBudget)
		}
		if m.hook != nil {
			m.hook.Close()
		}
		if m.events != nil {
			m.events.Close()
		}
	}
}

func (m *OutboundMonitoring) relayHistoryUpdates() {
	if m == nil || m.hook == nil || m.events == nil {
		return
	}
	// Containment: the relay lives as long as the box; a panic here (observable
	// races during teardown) would abort the in-process Android app.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("monitoring: relayHistoryUpdates panic: %v", r)
		}
	}()
	observer := observable.NewObserver(m.hook, 4)
	ch, done, err := observer.Subscribe()
	if err != nil {
		return
	}
	defer observer.UnSubscribe(ch)
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-done:
			return
		case _, ok := <-ch:
			if !ok {
				return
			}
			m.events.Publish(GroupEvent{})
		}
	}
}

func Get(ctx context.Context) *OutboundMonitoring {
	_ = ctx
	if m := active.Load(); m != nil {
		return m
	}
	return &OutboundMonitoring{}
}

func RealTag(detour adapter.Outbound) string {
	if group, isGroup := detour.(adapter.OutboundGroup); isGroup {
		tag := group.Now()
		if tag != "" {
			return tag
		}
	}
	return detour.Tag()
}

// TestNow probes a single outbound/endpoint tag, or every leaf if tag is a group.
func (m *OutboundMonitoring) TestNow(outboundTag string) error {
	return m.TestNowContext(nil, outboundTag)
}

// TestNowContext is like TestNow but also cancels when caller (e.g. gRPC) ends.
func (m *OutboundMonitoring) TestNowContext(caller context.Context, outboundTag string) error {
	if m == nil || m.box == nil || m.history == nil || outboundTag == "" {
		return nil
	}

	m.probesInFlight.Add(1)
	defer m.probesInFlight.Done()

	parent, cancel := mergeProbeParent(m.ctx, caller)
	defer cancel()
	if err := parent.Err(); err != nil {
		return err
	}

	if ob, ok := m.box.Outbound().Outbound(outboundTag); ok {
		if group, isGroup := ob.(adapter.OutboundGroup); isGroup {
			return m.testGroupLeaves(parent, group)
		}
		return m.testDialer(parent, ob, ob)
	}
	if ep, ok := m.box.Endpoint().Get(outboundTag); ok {
		return m.testDialer(parent, ep, ep)
	}
	return nil
}

// mergeProbeParent cancels when either the monitor lifetime or the caller ends.
func mergeProbeParent(monitor, caller context.Context) (context.Context, context.CancelFunc) {
	if monitor == nil {
		monitor = context.Background()
	}
	if caller == nil {
		// Still return a cancelable child so callers can defer cancel safely.
		return context.WithCancel(monitor)
	}
	ctx, cancel := context.WithCancel(monitor)
	go func() {
		select {
		case <-caller.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func (m *OutboundMonitoring) testGroupLeaves(parent context.Context, group adapter.OutboundGroup) error {
	type leaf struct {
		dialer N.Dialer
		source adapter.Outbound
		tag    string
	}
	var leaves []leaf
	for _, itemTag := range group.All() {
		if ob, ok := m.box.Outbound().Outbound(itemTag); ok {
			if _, nested := ob.(adapter.OutboundGroup); nested {
				continue
			}
			leaves = append(leaves, leaf{dialer: ob, source: ob, tag: itemTag})
			continue
		}
		if ep, ok := m.box.Endpoint().Get(itemTag); ok {
			leaves = append(leaves, leaf{dialer: ep, source: ep, tag: itemTag})
		}
	}
	if len(leaves) == 0 {
		if now := group.Now(); now != "" {
			// Nested TestNowContext would double-count probesInFlight; probe inline.
			if ob, ok := m.box.Outbound().Outbound(now); ok {
				if _, isGroup := ob.(adapter.OutboundGroup); !isGroup {
					return m.testDialer(parent, ob, ob)
				}
			}
			if ep, ok := m.box.Endpoint().Get(now); ok {
				return m.testDialer(parent, ep, ep)
			}
		}
		return nil
	}

	if parent == nil {
		parent = context.Background()
	}
	b, _ := batch.New(parent, batch.WithConcurrencyNum[any](8))
	var mu sync.Mutex
	var firstErr error
	for _, l := range leaves {
		leaf := l
		b.Go(leaf.tag, func() (any, error) {
			// Containment: batch runs closures on bare goroutines; an unrecovered
			// panic in dialer code aborts the whole in-process Android app.
			defer func() {
				if r := recover(); r != nil {
					log.Printf("monitoring: probe panic tag=%s: %v", leaf.tag, r)
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("probe panic on %s: %v", leaf.tag, r)
					}
					mu.Unlock()
				}
			}()
			err := m.testDialer(parent, leaf.dialer, leaf.source)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
			return nil, nil
		})
	}
	_ = b.Wait()
	return firstErr
}

func strategySamples(strategy string) int {
	switch strings.ToLower(strings.TrimSpace(strategy)) {
	case "fastaverage", "fast_average", "fast-average":
		return 3
	case "stress":
		return 10
	default:
		return 1
	}
}

func (m *OutboundMonitoring) resolveURLs() []string {
	var urls []string
	if m.testURLs != nil {
		for _, u := range m.testURLs() {
			u = strings.TrimSpace(u)
			if u != "" {
				urls = append(urls, u)
			}
		}
	}
	return urls
}

func (m *OutboundMonitoring) testDialer(parent context.Context, dialer N.Dialer, source adapter.Outbound) error {
	if parent == nil {
		parent = context.Background()
	}

	urls := m.resolveURLs()
	tag := RealTag(source)
	if tag == "" && source != nil {
		tag = source.Tag()
	}
	if tag == "" {
		return nil
	}
	if len(urls) == 0 {
		m.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
			Time:  time.Now(),
			Delay: FailDelay,
		})
		return nil
	}

	strat := "single"
	if m.strategy != nil {
		strat = m.strategy()
	}
	samples := strategySamples(strat)
	if samples < 1 {
		samples = 1
	}

	var sum uint32
	var okCount int
	var lastErr error
	for i := 0; i < samples; i++ {
		if err := parent.Err(); err != nil {
			lastErr = err
			break
		}
		delay, err := m.raceURLs(parent, dialer, urls)
		if err != nil || delay == 0 || delay > MaxSuccessDelay {
			lastErr = err
			continue
		}
		sum += uint32(delay)
		okCount++
	}

	if okCount == 0 {
		m.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
			Time:  time.Now(),
			Delay: FailDelay,
		})
		return lastErr
	}
	avg := uint16(sum / uint32(okCount))
	if avg == 0 {
		avg = 1
	}
	m.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
		Time:  time.Now(),
		Delay: avg,
	})
	return nil
}

// raceURLs probes all URLs in parallel; first success within probeTimeout wins.
func (m *OutboundMonitoring) raceURLs(parent context.Context, dialer N.Dialer, urls []string) (uint16, error) {
	timeout := m.probeTimeout()
	if len(urls) == 1 {
		testCtx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()
		return urltest.URLTest(testCtx, urls[0], dialer)
	}

	type result struct {
		delay uint16
		err   error
	}
	ch := make(chan result, len(urls))
	raceCtx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	for _, u := range urls {
		link := u
		go func() {
			// Contained: a panic in urltest/protocol code on this bare goroutine
			// would abort the whole in-process app (Android single-process core).
			defer func() {
				if r := recover(); r != nil {
					log.Printf("monitoring: race probe panic url=%s: %v", link, r)
					ch <- result{err: fmt.Errorf("probe panic: %v", r)}
				}
			}()
			d, err := urltest.URLTest(raceCtx, link, dialer)
			ch <- result{delay: d, err: err}
		}()
	}

	var lastErr error
	remaining := len(urls)
	for remaining > 0 {
		select {
		case <-raceCtx.Done():
			if lastErr == nil {
				lastErr = raceCtx.Err()
			}
			return 0, lastErr
		case r := <-ch:
			remaining--
			if r.err == nil && r.delay > 0 && r.delay <= MaxSuccessDelay {
				cancel()
				return r.delay, nil
			}
			if r.err != nil {
				lastErr = r.err
			}
		}
	}
	return 0, lastErr
}

func (m *OutboundMonitoring) OutboundsHistory(groupTag string) map[string]*adapter.URLTestHistory {
	_ = groupTag
	out := make(map[string]*adapter.URLTestHistory)
	if m == nil || m.history == nil || m.box == nil {
		return out
	}

	load := func(tag string) {
		if tag == "" {
			return
		}
		if h := m.history.LoadURLTestHistory(tag); h != nil {
			out[tag] = h
		}
	}

	for _, it := range m.box.Outbound().Outbounds() {
		load(it.Tag())
		load(RealTag(it))
		if group, ok := it.(adapter.OutboundGroup); ok {
			for _, itemTag := range group.All() {
				load(itemTag)
			}
		}
	}
	for _, it := range m.box.Endpoint().Endpoints() {
		load(it.Tag())
		load(RealTag(it))
	}
	return out
}

func (m *OutboundMonitoring) SubscribeGroup(groupTag string) (<-chan GroupEvent, error) {
	_ = groupTag
	if m == nil || m.events == nil {
		return make(chan GroupEvent), nil
	}
	return m.events.Subscribe(4), nil
}

func (m *OutboundMonitoring) UnsubscribeGroup(groupTag string, observer <-chan GroupEvent) error {
	_ = groupTag
	if m == nil || m.events == nil {
		return nil
	}
	m.events.Unsubscribe(observer)
	return nil
}
