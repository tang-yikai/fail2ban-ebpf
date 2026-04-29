package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

type BanFilter struct {
	localIPs  map[uint32]struct{}
	whitelist []net.IPNet
}

func NewBanFilter(cfg Config) (*BanFilter, error) {
	localIPs, err := discoverLocalIPv4s()
	if err != nil {
		return nil, err
	}
	localIPs[binary.LittleEndian.Uint32(net.IPv4(127, 0, 0, 1).To4())] = struct{}{}

	whitelist := make([]net.IPNet, 0, len(cfg.Whitelist.Entries))
	for _, entry := range cfg.Whitelist.Entries {
		ipNet, err := parseWhitelistEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("parse whitelist entry %q: %w", entry, err)
		}
		whitelist = append(whitelist, ipNet)
	}

	return &BanFilter{
		localIPs:  localIPs,
		whitelist: whitelist,
	}, nil
}

func (f *BanFilter) Check(ip uint32) (bool, string) {
	if ip == 0 {
		return false, "unknown_ip"
	}
	if _, exists := f.localIPs[ip]; exists {
		return false, "local_ip"
	}

	parsedIP := rawIPv4(ip)
	for _, network := range f.whitelist {
		if network.Contains(parsedIP) {
			return false, "whitelist"
		}
	}

	return true, ""
}

func discoverLocalIPv4s() (map[uint32]struct{}, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	localIPs := make(map[uint32]struct{})
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("list addresses for %s: %w", iface.Name, err)
		}
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			default:
				continue
			}

			ipv4 := ip.To4()
			if ipv4 == nil {
				continue
			}
			localIPs[binary.LittleEndian.Uint32(ipv4)] = struct{}{}
		}
	}

	return localIPs, nil
}

func parseWhitelistEntry(entry string) (net.IPNet, error) {
	if strings.Contains(entry, "/") {
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return net.IPNet{}, err
		}
		network.IP = network.IP.To4()
		if network.IP == nil {
			return net.IPNet{}, fmt.Errorf("only IPv4 CIDR is supported")
		}
		return *network, nil
	}

	ip := net.ParseIP(entry)
	if ip == nil {
		return net.IPNet{}, fmt.Errorf("invalid IP")
	}
	ip = ip.To4()
	if ip == nil {
		return net.IPNet{}, fmt.Errorf("only IPv4 addresses are supported")
	}

	return net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(32, 32),
	}, nil
}

func rawIPv4(raw uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, raw)
	return ip
}
