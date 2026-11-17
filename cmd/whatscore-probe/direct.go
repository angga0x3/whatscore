package main

import (
	"context"
	"time"

	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
)

type directDevices struct{ d *dispatcher }

func (s directDevices) Devices(ctx context.Context, accounts []string) ([]string, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	node, err := stanza.BuildDeviceQuery(id, accounts)
	if err != nil {
		return nil, err
	}
	reply, err := s.d.request(ctx, node, 20*time.Second)
	if err != nil {
		return nil, err
	}
	return stanza.ParseDeviceQuery(reply)
}

type directBundles struct{ d *dispatcher }

func (s directBundles) PreKeyBundle(ctx context.Context, peer string) (*signal.PreKeyBundle, error) {
	return fetchPreKeyBundle(ctx, s.d, peer)
}
