package main

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	wabinary "github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/protocol/noise"
)

// dispatcher owns the connection's read loop.
//
// Only one goroutine may read a secure connection, so every consumer goes
// through here: an iq reply resolves the waiter registered for its id, and
// everything else is handed to onNode. The earlier code had each step read for
// itself, which silently discarded whatever arrived in between — and what
// arrives in between is exactly the inbound backlog this probe exists to read.
type dispatcher struct {
	sc     noise.SecureConn
	codec  wabinary.Codec
	onNode func(context.Context, *wabinary.Node)

	mu      sync.Mutex
	waiters map[string]chan *wabinary.Node

	stopOnce sync.Once
	stop     chan struct{}
	err      error
}

func newDispatcher(sc noise.SecureConn, codec wabinary.Codec) *dispatcher {
	return &dispatcher{
		sc:      sc,
		codec:   codec,
		waiters: make(map[string]chan *wabinary.Node),
		stop:    make(chan struct{}),
	}
}

// run reads until the context ends, the socket closes, or stop is called.
func (d *dispatcher) run(ctx context.Context) {
	defer d.closeWaiters()
	for {
		select {
		case <-d.stop:
			return
		case <-ctx.Done():
			return
		default:
		}
		frame, err := d.sc.ReadFrame(ctx)
		if err != nil {
			d.mu.Lock()
			d.err = err
			d.mu.Unlock()
			return
		}
		node, err := d.codec.Decode(bytes.NewReader(frame))
		if err != nil {
			path, werr := dumpFrame(frame)
			if werr == nil {
				fmt.Printf("undecodable stanza (%d bytes): %v (kept at %s)\n", len(frame), err, path)
			} else {
				fmt.Printf("undecodable stanza (%d bytes): %v\n", len(frame), err)
			}
			continue
		}

		if node.Tag == "iq" && node.Attrs["id"] != "" {
			d.mu.Lock()
			waiter, ok := d.waiters[node.Attrs["id"]]
			if ok {
				delete(d.waiters, node.Attrs["id"])
			}
			d.mu.Unlock()
			if ok {
				waiter <- node
				continue
			}
		}
		if d.onNode != nil {
			d.onNode(ctx, node)
		}
	}
}

// request sends a node and waits for the iq reply with the same id.
func (d *dispatcher) request(ctx context.Context, node *wabinary.Node, timeout time.Duration) (*wabinary.Node, error) {
	id := node.Attrs["id"]
	if id == "" {
		return nil, fmt.Errorf("iq has no id")
	}
	waiter := make(chan *wabinary.Node, 1)
	d.mu.Lock()
	d.waiters[id] = waiter
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.waiters, id)
		d.mu.Unlock()
	}()

	frame, err := d.codec.Encode(node)
	if err != nil {
		return nil, fmt.Errorf("encode iq: %w", err)
	}
	if err := d.sc.WriteFrame(ctx, frame); err != nil {
		return nil, fmt.Errorf("send iq: %w", err)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case reply, ok := <-waiter:
		if !ok || reply == nil {
			// The read loop ended, taking every waiter with it. A closed
			// channel must not be mistaken for a reply.
			if err := d.readError(); err != nil {
				return nil, fmt.Errorf("connection ended while waiting for iq %s: %w", id, err)
			}
			return nil, fmt.Errorf("connection ended while waiting for iq %s", id)
		}
		if reply.Attrs["type"] == "error" {
			return nil, fmt.Errorf("server rejected iq %s: %s", id, describeError(reply))
		}
		return reply, nil
	case <-timer.C:
		return nil, fmt.Errorf("no reply to iq %s within %s", id, timeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *dispatcher) shutdown() {
	d.stopOnce.Do(func() { close(d.stop) })
}

func (d *dispatcher) closeWaiters() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, waiter := range d.waiters {
		close(waiter)
		delete(d.waiters, id)
	}
}

// readError reports why the read loop ended, so a waiter that is released by a
// closing connection can say why instead of reporting an empty reply.
func (d *dispatcher) readError() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}
