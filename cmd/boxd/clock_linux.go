//go:build linux

package main

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// ptpDevice is the paravirtual PTP clock KVM exposes to the guest; its reads
// are the host's CLOCK_REALTIME, which makes it the one time source in the
// guest that does not come from the guest's own, possibly frozen, clock.
const ptpDevice = "/dev/ptp0"

// ptpClock reads host time through the PTP device and adopts it.
type ptpClock struct {
	once    sync.Once
	openErr error
	clockID int32
}

func newWallClockSource() wallClockSource { return &ptpClock{} }

func (p *ptpClock) open() error {
	p.once.Do(func() {
		fd, err := unix.Open(ptpDevice, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			p.openErr = fmt.Errorf("open %s: %w", ptpDevice, err)
			return
		}
		// A dynamic POSIX clock is addressed by its file descriptor:
		// FD_TO_CLOCKID(fd) = (~fd << 3) | CLOCKFD, CLOCKFD = 3. The descriptor
		// is kept open for the life of the process; the clock id is only valid
		// while it is.
		p.clockID = (^int32(fd) << 3) | 3
	})
	return p.openErr
}

func (p *ptpClock) hostTime() (time.Time, error) {
	if err := p.open(); err != nil {
		return time.Time{}, err
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(p.clockID, &ts); err != nil {
		return time.Time{}, fmt.Errorf("clock_gettime(%s): %w", ptpDevice, err)
	}
	return time.Unix(ts.Sec, ts.Nsec), nil
}

func (p *ptpClock) set(t time.Time) error {
	ts := unix.NsecToTimespec(t.UnixNano())
	if err := unix.ClockSettime(unix.CLOCK_REALTIME, &ts); err != nil {
		return fmt.Errorf("clock_settime(CLOCK_REALTIME): %w", err)
	}
	return nil
}
