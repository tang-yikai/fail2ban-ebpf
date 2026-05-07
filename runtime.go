package main

import (
	"errors"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

type Runtime struct {
	reader     *perf.Reader
	kpAccept   link.Link
	tpFork     link.Link
	tpExit     link.Link
	pamProbe   link.Link
	xdpBlocker *XDPBlocker
}

func (r *Runtime) Close() error {
	var closeErr error

	if r.reader != nil {
		closeErr = errors.Join(closeErr, r.reader.Close())
	}
	closeErr = errors.Join(
		closeErr,
		closeLink(r.pamProbe),
		closeLink(r.tpExit),
		closeLink(r.tpFork),
		closeLink(r.kpAccept),
	)
	if r.xdpBlocker != nil {
		closeErr = errors.Join(closeErr, r.xdpBlocker.Close())
	}

	return closeErr
}

func closeLink(l link.Link) error {
	if l == nil {
		return nil
	}
	return l.Close()
}

func isClosedPerfError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, perf.ErrClosed) || errors.Is(err, os.ErrClosed)
}
