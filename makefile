APP := fail2ban-ebpf
GO ?= go
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_M),x86_64)
TARGET_ARCH ?= amd64
else ifeq ($(UNAME_M),aarch64)
TARGET_ARCH ?= arm64
else ifeq ($(UNAME_M),arm64)
TARGET_ARCH ?= arm64
else
TARGET_ARCH ?= amd64
endif

.PHONY: all gen build run clean test lint coverage help frontend

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 仅生成 eBPF 代码（不包含前端）
gen: vmlinux.h
	@echo "==> Generating eBPF bindings for $(TARGET_ARCH)"
	BPF2GO_ARCH=$(TARGET_ARCH) $(GO) generate ./...

build: gen
	@echo "==> Building"
	CGO_ENABLED=0 $(GO) build -ldflags="-s -w" -o $(APP) .

clean:
	@echo "==> Cleaning"
	rm -vf $(APP) *_bpfeb.go *_bpfel.go *.o
