package main

import (
	"sync"
	"time"
)

type BanManager struct {
	mu        sync.Mutex
	window    time.Duration
	duration  time.Duration
	threshold int
	attempts  map[uint32][]time.Time
	banned    map[uint32]time.Time
}

func NewBanManager(cfg Config) *BanManager {
	return &BanManager{
		window:    time.Duration(cfg.Ban.WindowMinutes) * time.Minute,
		duration:  time.Duration(cfg.Ban.DurationMinutes) * time.Minute,
		threshold: cfg.Ban.Threshold,
		attempts:  make(map[uint32][]time.Time),
		banned:    make(map[uint32]time.Time),
	}
}

func (m *BanManager) RegisterFailure(ip uint32, now time.Time) (bool, time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if expiresAt, exists := m.banned[ip]; exists && !expiresAt.IsZero() && now.Before(expiresAt) {
		return false, expiresAt
	}
	if expiresAt, exists := m.banned[ip]; exists && expiresAt.IsZero() {
		return false, expiresAt
	}

	cutoff := now.Add(-m.window)
	attempts := m.attempts[ip][:0]
	for _, ts := range m.attempts[ip] {
		if !ts.Before(cutoff) {
			attempts = append(attempts, ts)
		}
	}
	attempts = append(attempts, now)
	m.attempts[ip] = attempts

	if len(attempts) < m.threshold {
		return false, time.Time{}
	}

	var expiresAt time.Time
	if m.duration > 0 {
		expiresAt = now.Add(m.duration)
	}
	m.banned[ip] = expiresAt
	delete(m.attempts, ip)
	return true, expiresAt
}

func (m *BanManager) Expired(now time.Time) []uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.duration <= 0 {
		return nil
	}

	var expired []uint32
	for ip, expiresAt := range m.banned {
		if !expiresAt.IsZero() && !now.Before(expiresAt) {
			expired = append(expired, ip)
			delete(m.banned, ip)
		}
	}
	return expired
}
