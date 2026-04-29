package main

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"
)

type EventLogger struct {
	file   *os.File
	logger *log.Logger
}

func NewEventLogger(path string) (*EventLogger, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("open log file %q: %w", path, err)
	}

	return &EventLogger{
		file:   file,
		logger: log.New(file, "", 0),
	}, nil
}

func (l *EventLogger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

func (l *EventLogger) Event(name string, fields map[string]interface{}) {
	if l == nil || l.logger == nil {
		return
	}

	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var builder strings.Builder
	builder.WriteString("time=")
	builder.WriteString(time.Now().Format(time.RFC3339))
	builder.WriteString(" event=")
	builder.WriteString(name)

	for _, key := range keys {
		builder.WriteString(" ")
		builder.WriteString(key)
		builder.WriteString("=")
		builder.WriteString(fmt.Sprint(fields[key]))
	}

	l.logger.Println(builder.String())
}
