package inbound

import (
	"context"
	"errors"
	"io"
	"net/netip"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/hops"
	"github.com/fitting-1c/evasion/internal/packet"
)

func Run(ctx context.Context, src capture.PacketSource, table *hops.Table, onRST func(remote netip.AddrPort, localPort uint16)) error {
	for {
		if ctx.Err() != nil {
			return nil
		}
		pkt, err := src.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		if pkt.Dir != core.DirectionInbound {
			continue
		}
		d, err := packet.Dissect(pkt.Data)
		if err != nil || d.Protocol != packet.ProtoTCP {
			continue
		}
		tcp, ok := d.TCP(pkt.Data)
		if !ok {
			continue
		}
		ip, ok := sourceAddr(d, pkt.Data)
		if !ok {
			continue
		}
		flags := tcp.Flags()
		if flags&(packet.FlagSYN|packet.FlagACK) == packet.FlagSYN|packet.FlagACK {
			if ttl, ok := packetTTL(d, pkt.Data); ok && table != nil {
				table.Observe(ip, ttl)
			}
		}
		if flags&packet.FlagRST != 0 && onRST != nil {
			onRST(netip.AddrPortFrom(ip, tcp.SrcPort()), tcp.DstPort())
		}
	}
}

func sourceAddr(d packet.Dissection, data []byte) (netip.Addr, bool) {
	switch d.Version {
	case packet.Version4:
		h, ok := d.IPv4(data)
		if !ok {
			return netip.Addr{}, false
		}
		addr, ok := netip.AddrFromSlice(h.Src())
		return addr.Unmap(), ok
	case packet.Version6:
		h, ok := d.IPv6(data)
		if !ok {
			return netip.Addr{}, false
		}
		addr, ok := netip.AddrFromSlice(h.Src())
		return addr, ok
	default:
		return netip.Addr{}, false
	}
}

func packetTTL(d packet.Dissection, data []byte) (uint8, bool) {
	switch d.Version {
	case packet.Version4:
		h, ok := d.IPv4(data)
		if ok {
			return h.TTL(), true
		}
	case packet.Version6:
		h, ok := d.IPv6(data)
		if ok {
			return h.HopLimit(), true
		}
	}
	return 0, false
}
