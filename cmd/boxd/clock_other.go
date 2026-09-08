//go:build !linux

package main

import (
	"errors"
	"time"
)

// boxd only runs inside a Linux microVM in production; this exists so the
// package builds and its tests run elsewhere.
type noWallClockSource struct{}

func newWallClockSource() wallClockSource { return noWallClockSource{} }

func (noWallClockSource) hostTime() (time.Time, error) {
	return time.Time{}, errors.New("host time source only available on linux")
}

func (noWallClockSource) set(time.Time) error {
	return errors.New("clock_settime only available on linux")
}
