package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	eventAuthResult       = 1
	eventPreauthShortConn = 2
)

type SSHEvent struct {
	Type       uint32
	Pid        uint32
	RemoteIP   uint32
	RetCode    uint32
	DurationNS uint64
}

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatalf("load config: %v", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		fatalf("remove memlock: %v", err)
	}

	objs := sshmonObjects{}
	if err := loadConfiguredSshmonObjects(&objs, cfg); err != nil {
		fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	eventLogger, err := NewEventLogger(cfg.Log.File)
	if err != nil {
		fatalf("create logger: %v", err)
	}

	banFilter, err := NewBanFilter(cfg)
	if err != nil {
		_ = eventLogger.Close()
		fatalf("create ban filter: %v", err)
	}

	xdpBlocker, err := NewXDPBlocker(cfg)
	if err != nil {
		_ = eventLogger.Close()
		fatalf("attach xdp: %v", err)
	}

	banManager := NewBanManager(cfg)

	port := cfg.SSH.Port
	var enabled uint8 = 1
	if err := objs.MonitoredPorts.Update(port, enabled, 0); err != nil {
		_ = xdpBlocker.Close()
		_ = eventLogger.Close()
		fatalf("failed to update port map: %v", err)
	}

	kpAccept, err := link.Kretprobe("inet_csk_accept", objs.HandleAcceptReturn, nil)
	if err != nil {
		_ = xdpBlocker.Close()
		_ = eventLogger.Close()
		fatalf("failed to attach kretprobe: %v", err)
	}

	tpFork, err := link.Tracepoint("sched", "sched_process_fork", objs.HandleFork, nil)
	if err != nil {
		_ = kpAccept.Close()
		_ = xdpBlocker.Close()
		_ = eventLogger.Close()
		fatalf("failed to attach sched_process_fork: %v", err)
	}

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil)
	if err != nil {
		_ = tpFork.Close()
		_ = kpAccept.Close()
		_ = xdpBlocker.Close()
		_ = eventLogger.Close()
		fatalf("failed to attach sched_process_exit: %v", err)
	}

	libPath := findLibPAM()
	if err := ensureExecutable(libPath); err != nil {
		eventLogger.Event("warning", map[string]interface{}{
			"message": fmt.Sprintf("could not ensure executable bit on %s: %v", libPath, err),
		})
	}

	ex, err := link.OpenExecutable(libPath)
	if err != nil {
		_ = tpExit.Close()
		_ = tpFork.Close()
		_ = kpAccept.Close()
		_ = xdpBlocker.Close()
		_ = eventLogger.Close()
		fatalf("open libpam: %v", err)
	}

	up, err := ex.Uretprobe("pam_authenticate", objs.HandlePamAuth, nil)
	if err != nil {
		_ = tpExit.Close()
		_ = tpFork.Close()
		_ = kpAccept.Close()
		_ = xdpBlocker.Close()
		_ = eventLogger.Close()
		fatalf("attach uretprobe: %v", err)
	}

	rd, err := perf.NewReader(objs.Events, os.Getpagesize()*64)
	if err != nil {
		_ = up.Close()
		_ = tpExit.Close()
		_ = tpFork.Close()
		_ = kpAccept.Close()
		_ = xdpBlocker.Close()
		_ = eventLogger.Close()
		fatalf("create perf reader: %v", err)
	}

	rt := &Runtime{
		reader:     rd,
		kpAccept:   kpAccept,
		tpFork:     tpFork,
		tpExit:     tpExit,
		pamProbe:   up,
		xdpBlocker: xdpBlocker,
		logger:     eventLogger,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eventLogger.Event("service_started", map[string]interface{}{
		"config":             *configPath,
		"libpam":             libPath,
		"log_file":           cfg.Log.File,
		"mode":               cfg.Mode,
		"short_conn_seconds": cfg.Ban.ShortConnSeconds,
		"ssh_port":           port,
		"threshold":          cfg.Ban.Threshold,
		"window_minutes":     cfg.Ban.WindowMinutes,
		"xdp_iface":          cfg.XDP.Iface,
		"xdp_mode":           xdpBlocker.Mode(),
	})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		runBanExpiryLoop(ctx, banManager, xdpBlocker, eventLogger)
	}()

	go func() {
		defer wg.Done()
		runPerfLoop(ctx, rd, banManager, banFilter, xdpBlocker, eventLogger, cfg)
	}()

	<-ctx.Done()
	eventLogger.Event("service_stopping", map[string]interface{}{
		"signal": ctx.Err().Error(),
	})

	if err := rd.Close(); err != nil && !isClosedPerfError(err) {
		eventLogger.Event("warning", map[string]interface{}{
			"message": fmt.Sprintf("close perf reader: %v", err),
		})
	}

	wg.Wait()
	eventLogger.Event("service_stopped", map[string]interface{}{})

	if err := rt.Close(); err != nil && !isClosedPerfError(err) {
		fatalf("shutdown resources: %v", err)
	}
}

// findLibPAM 自动适配架构并动态查找 libpam 路径
func findLibPAM() string {
	var searchPaths []string

	arch := runtime.GOARCH
	is64bit := strings.Contains(arch, "64")

	if is64bit {
		searchPaths = append(searchPaths,
			"/usr/lib/x86_64-linux-gnu/libpam.so.0",
			"/usr/lib64/libpam.so.0",
			"/lib/x86_64-linux-gnu/libpam.so.0",
			"/lib64/libpam.so.0",
		)
	}

	if arch == "arm64" {
		searchPaths = append(searchPaths,
			"/usr/lib/aarch64-linux-gnu/libpam.so.0",
			"/lib/aarch64-linux-gnu/libpam.so.0",
		)
	}

	searchPaths = append(searchPaths,
		"/usr/lib/libpam.so.0",
		"/lib/libpam.so.0",
	)

	for _, p := range searchPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return "libpam.so.0"
}

func ensureExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	mode := info.Mode()
	if mode&0111 == 0 {
		err := os.Chmod(path, mode|0111)
		if err != nil {
			return fmt.Errorf("failed to chmod +x %s: %w (try running as sudo)", path, err)
		}
	}
	return nil
}

func ipv4String(raw uint32) string {
	if raw == 0 {
		return "UNKNOWN"
	}

	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, raw)
	return ip.String()
}

func runBanExpiryLoop(ctx context.Context, banManager *BanManager, blocker *XDPBlocker, logger *EventLogger) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for _, ip := range banManager.Expired(time.Now()) {
				if err := blocker.Unban(ip); err != nil {
					logger.Event("warning", map[string]interface{}{
						"message": fmt.Sprintf("failed to unban %s: %v", ipv4String(ip), err),
					})
					continue
				}
				logger.Event("ip_unblocked", map[string]interface{}{
					"ip": ipv4String(ip),
				})
			}
		case <-ctx.Done():
			return
		}
	}
}

func runPerfLoop(
	ctx context.Context,
	reader *perf.Reader,
	banManager *BanManager,
	banFilter *BanFilter,
	blocker *XDPBlocker,
	logger *EventLogger,
	cfg Config,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if isClosedPerfError(err) || ctx.Err() != nil {
				return
			}
			logger.Event("warning", map[string]interface{}{
				"message": fmt.Sprintf("read perf event: %v", err),
			})
			continue
		}

		if record.LostSamples > 0 {
			logger.Event("warning", map[string]interface{}{
				"message": fmt.Sprintf("lost %d perf samples", record.LostSamples),
			})
			continue
		}

		var event SSHEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Event("warning", map[string]interface{}{
				"message": fmt.Sprintf("decode perf event: %v", err),
			})
			continue
		}

		fields := map[string]interface{}{
			"ip":  ipv4String(event.RemoteIP),
			"pid": event.Pid,
		}
		fields["ret"] = event.RetCode

		switch event.Type {
		case eventAuthResult:
			if event.RetCode == 0 {
				logger.Event("auth_success", fields)
				continue
			}

			logger.Event("auth_failed", fields)

			if event.RemoteIP == 0 {
				continue
			}

			if banned, expiresAt := banManager.RegisterFailure(event.RemoteIP, time.Now()); banned {
				logBanResult(banFilter, blocker, logger, fields["ip"], event.RemoteIP, expiresAt, map[string]interface{}{
					"reason":         "auth_failed",
					"threshold":      cfg.Ban.Threshold,
					"window_minutes": cfg.Ban.WindowMinutes,
				})
			}
		case eventPreauthShortConn:
			fields["duration_ms"] = event.DurationNS / uint64(time.Millisecond)
			logger.Event("preauth_short_conn", fields)

			if event.RemoteIP == 0 {
				continue
			}
			if banned, expiresAt := banManager.RegisterFailure(event.RemoteIP, time.Now()); banned {
				logBanResult(banFilter, blocker, logger, fields["ip"], event.RemoteIP, expiresAt, map[string]interface{}{
					"reason":             "preauth_short_conn",
					"short_conn_seconds": cfg.Ban.ShortConnSeconds,
					"threshold":          cfg.Ban.Threshold,
					"window_minutes":     cfg.Ban.WindowMinutes,
				})
			}
		default:
			logger.Event("warning", map[string]interface{}{
				"message": fmt.Sprintf("unknown event type %d", event.Type),
			})
		}
	}
}

func loadConfiguredSshmonObjects(objs *sshmonObjects, cfg Config) error {
	spec, err := loadSshmon()
	if err != nil {
		return err
	}

	if preauthVar := spec.Variables["preauth_short_conn_ns"]; preauthVar != nil {
		if err := preauthVar.Set(uint64(cfg.Ban.ShortConnSeconds) * uint64(time.Second)); err != nil {
			return fmt.Errorf("set preauth_short_conn_ns: %w", err)
		}
	}
	if modeVar := spec.Variables["aggressive_mode"]; modeVar != nil {
		var enabled uint8
		if cfg.Mode == "aggressive" {
			enabled = 1
		}
		if err := modeVar.Set(enabled); err != nil {
			return fmt.Errorf("set aggressive_mode: %w", err)
		}
	}

	return spec.LoadAndAssign(objs, nil)
}

func logBanResult(
	banFilter *BanFilter,
	blocker *XDPBlocker,
	logger *EventLogger,
	ipValue interface{},
	rawIP uint32,
	expiresAt time.Time,
	fields map[string]interface{},
) {
	if allowed, reason := banFilter.Check(rawIP); !allowed {
		fields["ip"] = ipValue
		if eventReason, exists := fields["reason"]; exists {
			fields["event_reason"] = eventReason
		}
		fields["skip_reason"] = reason
		delete(fields, "reason")
		logger.Event("ban_skipped", fields)
		return
	}

	if err := blocker.Ban(rawIP); err != nil {
		logger.Event("warning", map[string]interface{}{
			"message": fmt.Sprintf("failed to ban %v: %v", ipValue, err),
		})
		return
	}

	fields["ip"] = ipValue
	if !expiresAt.IsZero() {
		fields["expires_at"] = expiresAt.Format(time.RFC3339)
	}
	logger.Event("ip_blocked", fields)
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
