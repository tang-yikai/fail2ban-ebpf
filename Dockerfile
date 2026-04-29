FROM golang:1.25-alpine AS builder

ENV GOPROXY="https://goproxy.cn,direct"

# 安装构建依赖（包含 LLVM、bpftool 和 libbpf 用于 eBPF）
RUN sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories && \
    apk add --no-cache git build-base linux-headers clang llvm lld bpftool libbpf-dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
RUN go generate ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/fail2ban-ebpf .

FROM alpine:3.20 

RUN sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories && \
    apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /out/fail2ban-ebpf /usr/local/bin/fail2ban-ebpf

ENTRYPOINT ["/usr/local/bin/fail2ban-ebpf"]
CMD ["-config", "/etc/fail2ban-ebpf/config.yaml"]
