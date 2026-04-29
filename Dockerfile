FROM docker.cnb.cool/lingjiancode/docker-builder/mygolang:1.25-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

RUN make build 

FROM docker.cnb.cool/lingjiancode/docker-builder/myalpine:3.20 

WORKDIR /app

COPY --from=builder /build/fail2ban-ebpf /usr/bin/fail2ban-ebpf

ENTRYPOINT ["/usr/bin/fail2ban-ebpf"]
CMD ["-config", "/etc/fail2ban-ebpf/config.yaml"]
