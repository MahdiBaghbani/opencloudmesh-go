// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package bounded provides a cardinality-bounded LRU container.
package bounded

import "container/list"

// LRU is a cardinality-bounded least-recently-used container. It is
// caller-serialized: it performs no internal locking, so the caller must
// synchronize concurrent access. A capacity of zero or less means unbounded.
type LRU[K comparable, V any] struct {
	capacity int
	order    *list.List
	items    map[K]*list.Element
}

// list elements only ever hold entry[K, V]; unwrap asserts that invariant.
func unwrap[K comparable, V any](el *list.Element) entry[K, V] {
	e, ok := el.Value.(entry[K, V])
	if !ok {
		panic("bounded: list element value is not entry[K, V]")
	}

	return e
}

type entry[K comparable, V any] struct {
	key   K
	value V
}

// NewLRU creates an LRU bounded to capacity entries.
func NewLRU[K comparable, V any](capacity int) *LRU[K, V] {
	return &LRU[K, V]{
		capacity: capacity,
		order:    list.New(),
		items:    map[K]*list.Element{},
	}
}

// Get returns the value for key and marks it most recently used.
func (l *LRU[K, V]) Get(key K) (V, bool) {
	el, ok := l.items[key]
	if !ok {
		var zero V

		return zero, false
	}

	l.order.MoveToFront(el)

	return unwrap[K, V](el).value, true
}

// Peek returns the value for key without changing recency order.
func (l *LRU[K, V]) Peek(key K) (V, bool) {
	el, ok := l.items[key]
	if !ok {
		var zero V

		return zero, false
	}

	return unwrap[K, V](el).value, true
}

// Set inserts or updates key, marks it most recently used, and evicts the
// least recently used entries beyond capacity.
func (l *LRU[K, V]) Set(key K, value V) {
	if el, ok := l.items[key]; ok {
		el.Value = entry[K, V]{key: key, value: value}
		l.order.MoveToFront(el)

		return
	}

	l.items[key] = l.order.PushFront(entry[K, V]{key: key, value: value})

	if l.capacity <= 0 {
		return
	}

	for l.order.Len() > l.capacity {
		back := l.order.Back()
		l.order.Remove(back)
		delete(l.items, unwrap[K, V](back).key)
	}
}

// Delete removes key.
func (l *LRU[K, V]) Delete(key K) {
	if el, ok := l.items[key]; ok {
		l.order.Remove(el)
		delete(l.items, key)
	}
}

// Len returns the number of entries.
func (l *LRU[K, V]) Len() int {
	return l.order.Len()
}

// RemoveIf deletes every entry for which match returns true.
func (l *LRU[K, V]) RemoveIf(match func(K, V) bool) {
	stale := []K{}

	for key, el := range l.items {
		if match(key, unwrap[K, V](el).value) {
			stale = append(stale, key)
		}
	}

	for _, key := range stale {
		l.Delete(key)
	}
}
