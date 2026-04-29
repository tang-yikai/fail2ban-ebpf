package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Mode string
	SSH  struct {
		Port uint16
	}
	XDP struct {
		Iface string
	}
	Ban struct {
		Threshold        int
		WindowMinutes    int
		DurationMinutes  int
		MaxBlockedIPs    uint32
		ShortConnSeconds int
	}
	Log struct {
		File string
	}
	Whitelist struct {
		Entries []string
	}
}

func defaultConfig() Config {
	cfg := Config{}
	cfg.Mode = "normal"
	cfg.SSH.Port = 22
	cfg.XDP.Iface = "eth0"
	cfg.Ban.Threshold = 3
	cfg.Ban.WindowMinutes = 10
	cfg.Ban.DurationMinutes = 1440
	cfg.Ban.MaxBlockedIPs = 262144
	cfg.Ban.ShortConnSeconds = 2
	cfg.Log.File = "./fail2ban-ebpf.log"
	return cfg
}

func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()

	file, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	section := ""
	listKey := ""
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := stripComment(scanner.Text())
		if strings.TrimSpace(line) == "" {
			continue
		}

		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
			section = strings.TrimSuffix(trimmed, ":")
			listKey = ""
			continue
		}
		if strings.HasPrefix(line, "  ") && strings.HasSuffix(trimmed, ":") {
			listKey = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			item = strings.Trim(item, `"'`)
			if err := applyConfigListItem(&cfg, section, listKey, item); err != nil {
				return cfg, fmt.Errorf("config line %d: %w", lineNo, err)
			}
			continue
		}
		listKey = ""

		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			return cfg, fmt.Errorf("config line %d: expected key: value", lineNo)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"'`)

		if err := applyConfigValue(&cfg, section, key, value); err != nil {
			return cfg, fmt.Errorf("config line %d: %w", lineNo, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return cfg, err
	}

	return cfg, cfg.validate()
}

func stripComment(line string) string {
	inQuotes := false
	var quoteChar rune

	for i, r := range line {
		switch {
		case (r == '"' || r == '\'') && !inQuotes:
			inQuotes = true
			quoteChar = r
		case inQuotes && r == quoteChar:
			inQuotes = false
		case r == '#' && !inQuotes:
			return strings.TrimRight(line[:i], " \t")
		}
	}

	return strings.TrimRight(line, " \t")
}

func applyConfigValue(cfg *Config, section, key, value string) error {
	switch section {
	case "":
		switch key {
		case "mode":
			cfg.Mode = value
			return nil
		}
	case "ssh":
		switch key {
		case "port":
			parsed, err := parseUint16(value)
			if err != nil {
				return err
			}
			cfg.SSH.Port = parsed
			return nil
		}
	case "xdp":
		switch key {
		case "iface":
			cfg.XDP.Iface = value
			return nil
		}
	case "ban":
		switch key {
		case "threshold":
			parsed, err := parsePositiveInt(value)
			if err != nil {
				return err
			}
			cfg.Ban.Threshold = parsed
			return nil
		case "window_minutes":
			parsed, err := parsePositiveInt(value)
			if err != nil {
				return err
			}
			cfg.Ban.WindowMinutes = parsed
			return nil
		case "duration_minutes":
			parsed, err := parseNonNegativeInt(value)
			if err != nil {
				return err
			}
			cfg.Ban.DurationMinutes = parsed
			return nil
		case "max_blocked_ips":
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid uint32 value %q", value)
			}
			cfg.Ban.MaxBlockedIPs = uint32(parsed)
			return nil
		case "short_conn_seconds":
			parsed, err := parsePositiveInt(value)
			if err != nil {
				return err
			}
			cfg.Ban.ShortConnSeconds = parsed
			return nil
		}
	case "log":
		switch key {
		case "file":
			cfg.Log.File = value
			return nil
		}
	}

	return fmt.Errorf("unknown config key %q in section %q", key, section)
}

func applyConfigListItem(cfg *Config, section, key, value string) error {
	switch section {
	case "whitelist":
		switch key {
		case "entries":
			cfg.Whitelist.Entries = append(cfg.Whitelist.Entries, value)
			return nil
		}
	}

	return fmt.Errorf("unknown list key %q in section %q", key, section)
}

func parseUint16(value string) (uint16, error) {
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid uint16 value %q", value)
	}
	return uint16(parsed), nil
}

func parsePositiveInt(value string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("invalid positive integer %q", value)
	}
	return parsed, nil
}

func parseNonNegativeInt(value string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("invalid non-negative integer %q", value)
	}
	return parsed, nil
}

func (c Config) validate() error {
	switch {
	case c.Mode != "normal" && c.Mode != "aggressive":
		return fmt.Errorf("mode must be one of: normal, aggressive")
	case c.SSH.Port == 0:
		return fmt.Errorf("ssh.port must be greater than 0")
	case c.XDP.Iface == "":
		return fmt.Errorf("xdp.iface must not be empty")
	case c.Ban.Threshold <= 0:
		return fmt.Errorf("ban.threshold must be greater than 0")
	case c.Ban.WindowMinutes <= 0:
		return fmt.Errorf("ban.window_minutes must be greater than 0")
	case c.Ban.MaxBlockedIPs == 0:
		return fmt.Errorf("ban.max_blocked_ips must be greater than 0")
	case c.Ban.ShortConnSeconds <= 0:
		return fmt.Errorf("ban.short_conn_seconds must be greater than 0")
	case c.Log.File == "":
		return fmt.Errorf("log.file must not be empty")
	}

	return nil
}
