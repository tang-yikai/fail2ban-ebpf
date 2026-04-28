package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf ssh_monitor.bpf.c

type SSHFailEvent struct {
	Pid      uint32
	RemoteIP uint32
	RetCode  uint32
}

func main() {
	// 1. 解除内存限制 (旧版本内核必需)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 2. 加载 eBPF 字节码
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// 3. 配置监控端口 (SSH 默认 22)
	// 如果你的 SSH 运行在非 22 端口，在此处修改
	var port uint16 = 22
	var enabled uint8 = 1
	if err := objs.MonitoredPorts.Update(port, enabled, 0); err != nil {
		log.Fatalf("failed to update port map: %v", err)
	}

	// 4. 绑定 Tracepoints
	kpAccept, err := link.Kretprobe("inet_csk_accept", objs.HandleAcceptReturn, nil)
	if err != nil {
		log.Fatalf("failed to attach kretprobe: %v", err)
	}
	defer kpAccept.Close()

	tpFork, _ := link.Tracepoint("sched", "sched_process_fork", objs.HandleFork, nil)
	defer tpFork.Close()

	tpExit, _ := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil)
	defer tpExit.Close()

	// 5. 绑定 Uprobe 到 libpam.so
	libPath := findLibPAM()
	if err := ensureExecutable(libPath); err != nil {
		log.Printf("Warning: could not ensure executable bit on %s: %v", libPath, err)
		// 继续尝试，如果失败 OpenExecutable 自然会报错
	}

	ex, err := link.OpenExecutable(libPath)
	if err != nil {
		log.Fatalf("open libpam: %v", err)
	}

	up, err := ex.Uretprobe("pam_authenticate", objs.HandlePamAuth, nil)
	if err != nil {
		log.Fatalf("attach uretprobe: %v", err)
	}
	defer up.Close()

	log.Printf("SSH Monitor running. Tracking port: %d, LibPAM: %s", port, libPath)

	// 6. 开启 Perf 事件读取逻辑
	rd, err := perf.NewReader(objs.Events, os.Getpagesize()*64)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	// 处理中断信号
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				continue
			}

			if record.LostSamples > 0 {
				log.Printf("Warning: lost %d samples", record.LostSamples)
				continue
			}

			var event SSHFailEvent
			binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)

			ipStr := "UNKNOWN"
			if event.RemoteIP != 0 {
				ip := make(net.IP, 4)
				binary.LittleEndian.PutUint32(ip, event.RemoteIP)
				ipStr = ip.String()
			}

			// 只要收到事件就打印，方便根据状态码判断
			status := "SUCCESS"
			if event.RetCode != 0 {
				status = fmt.Sprintf("FAILED(code:%d)", event.RetCode)
			}

			fmt.Printf("[DEBUG] Event Received | PID: %d | IP: %s | Status: %s\n",
				event.Pid, ipStr, status)
		}
	}()

	<-stop
}

// 辅助函数：根据发行版查找 libpam 路径
func findLibPAM() string {
	paths := []string{
		"/usr/lib/x86_64-linux-gnu/libpam.so.0", // Ubuntu/Debian
		"/usr/lib64/libpam.so.0",                // CentOS/RHEL
		"/lib/x86_64-linux-gnu/libpam.so.0",
		"/lib64/libpam.so.0",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "libpam.so.0" // 回退到系统查找
}

// ensureExecutable 检查并尝试为文件添加执行权限
func ensureExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	mode := info.Mode()
	// 检查是否具备任何执行权限 (Owner/Group/Other)
	if mode&0111 == 0 {
		log.Printf("Detected libpam without executable bit, attempting to fix: %s", path)
		// 为文件添加执行权限 (保持原有权限并加上 +x)
		// os.Chmod 会自动跟随符号链接修改目标文件
		err := os.Chmod(path, mode|0111)
		if err != nil {
			return fmt.Errorf("failed to chmod +x %s: %w (try running as sudo)", path, err)
		}
	}
	return nil
}
