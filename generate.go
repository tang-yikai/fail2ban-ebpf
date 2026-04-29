package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 sshmon ssh_monitor.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 xdp xdp.bpf.c
