FROM docker.cnb.cool/lingjiancode/docker-builder/mygolang:1.25-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN make build 

FROM docker.cnb.cool/lingjiancode/docker-builder/myalpine:3.20 

WORKDIR /app

COPY --from=builder /build/fail2ban-ebpf /opt/fail2ban-ebpf

ENTRYPOINT ["/opt/fail2ban-ebpf"]
