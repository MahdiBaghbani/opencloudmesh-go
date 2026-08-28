// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"context"
	"sync"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func newLateSweepStops(store *validatorcore.Core) *lateSweepStops {
	if store == nil {
		return nil
	}

	return &lateSweepStops{}
}

// lateSweepStops is a bag of stop funcs started after the store sweeps.
// StopRetentionSweep joins the bag so a late-started runner cannot outlive
// the existing shutdown seat.
type lateSweepStops struct {
	mu    sync.Mutex
	stops []func()
}

func (s *lateSweepStops) Add(stop func()) {
	if s == nil || stop == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.stops = append(s.stops, stop)
}

// Stop joins every registered late stop. Safe on a nil bag.
func (s *lateSweepStops) Stop() {
	if s == nil {
		return
	}

	s.mu.Lock()
	stops := append([]func(){}, s.stops...)
	s.mu.Unlock()

	for _, stop := range stops {
		stop()
	}
}

// startStallSweep starts the hourly stalled active-run sweep after a
// successful Attach, alongside the retention expiry loop. The returned func
// cancels the loop and waits for the goroutine to exit so shutdown can close
// persistence safely.
func startStallSweep(store *validatorcore.Core) context.CancelFunc {
	if store == nil {
		return nil
	}

	sweepCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)

		store.StartStallSweep(sweepCtx)
	}()

	return func() {
		cancel()
		<-done
	}
}

// joinStoreSweepStops folds the store maintenance stop funcs into the single
// shutdown hook BuildResult carries, so the existing shutdown call site
// cancels and joins every sweep goroutine. Nil when no store is wired.
func joinStoreSweepStops(stops ...context.CancelFunc) context.CancelFunc {
	active := make([]context.CancelFunc, 0, len(stops))

	for _, stop := range stops {
		if stop != nil {
			active = append(active, stop)
		}
	}

	if len(active) == 0 {
		return nil
	}

	return func() {
		for _, stop := range active {
			stop()
		}
	}
}
