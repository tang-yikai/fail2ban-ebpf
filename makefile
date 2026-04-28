APP := fail2ban-ebpf
GO ?= go

.PHONY: all gen build run clean test lint coverage help frontend

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 仅生成 eBPF 代码（不包含前端）
gen: vmlinux.h
	$(GO) generate $(BPF_GEN_DIR)

build: gen
	@echo "==> Building"
	$(GO) build -o $(APP)

clean:
	@echo "==> Cleaning"
	rm -vf $(APP) *_bpfeb.go *_bpfel.go *.o
