// Package netbind находит физический сетевой адаптер и привязывает к нему
// исходящие соединения. Нужен, когда поверх системы поднят сторонний
// TUN-VPN: маршрут по умолчанию уходит в туннель, десинк внутри туннеля
// бесполезен, а соединение, привязанное к физическому адаптеру, идёт мимо
// туннеля и попадает под обычный перехват.
package netbind

import (
	"context"
	"net"
	"strings"
	"time"
)

// Adapter — сетевой адаптер в объёме, нужном для выбора маршрута.
type Adapter struct {
	Index       uint32
	Name        string
	Description string
	// Hardware — Ethernet или Wi-Fi по типу интерфейса.
	Hardware bool
	Up       bool
	Gateway  bool
	Metric   uint32
}

// Route описывает, куда сейчас уходит трафик по умолчанию.
type Route struct {
	// Tunnel — маршрут по умолчанию ведёт не в физический адаптер.
	Tunnel   bool
	Default  Adapter
	Physical Adapter
}

var virtualMarkers = []string{
	"wintun", "tap-", "tap ", "tun", "vpn", "virtual", "vmware", "virtualbox",
	"hyper-v", "wireguard", "xray", "sing-box", "loopback", "bluetooth",
}

func looksVirtual(a Adapter) bool {
	text := strings.ToLower(a.Name + " " + a.Description)
	for _, marker := range virtualMarkers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func physical(a Adapter) bool {
	return a.Hardware && a.Up && a.Gateway && !looksVirtual(a)
}

// Classify выбирает физический адаптер и решает, перехвачен ли маршрут по
// умолчанию туннелем. defaultIndex — индекс интерфейса лучшего маршрута наружу.
func Classify(adapters []Adapter, defaultIndex uint32) Route {
	var route Route
	found := false
	for _, a := range adapters {
		if a.Index == defaultIndex {
			route.Default = a
		}
		if !physical(a) {
			continue
		}
		if !found || a.Metric < route.Physical.Metric {
			route.Physical = a
			found = true
		}
	}
	if !found || defaultIndex == 0 {
		return route
	}
	route.Tunnel = !physical(route.Default)
	return route
}

// DialContextFunc совпадает по форме с net.Dialer.DialContext.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Dialer возвращает функцию соединения, привязанную к адаптеру с данным
// индексом. Имена разрешаются системным резолвером; само соединение идёт
// только по IPv4, чтобы привязка была однозначной.
func Dialer(index uint32) DialContextFunc {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: bindControl(index)}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network == "tcp" {
			network = "tcp4"
		}
		return d.DialContext(ctx, network, address)
	}
}
