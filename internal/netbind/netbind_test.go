package netbind

import "testing"

func TestClassify(t *testing.T) {
	eth := Adapter{Index: 5, Name: "Ethernet", Description: "Realtek PCIe GbE", Hardware: true, Up: true, Gateway: true, Metric: 25}
	wifi := Adapter{Index: 7, Name: "Wi-Fi", Description: "Intel AX200", Hardware: true, Up: true, Gateway: true, Metric: 40}
	tun := Adapter{Index: 30, Name: "happ-xray", Description: "Xray Tunnel", Up: true, Metric: 1}
	radmin := Adapter{Index: 9, Name: "Radmin VPN", Description: "Famatech Radmin VPN Ethernet Adapter", Hardware: true, Up: true}
	vmnet := Adapter{Index: 11, Name: "VMware Network Adapter VMnet8", Hardware: true, Up: true}
	tap := Adapter{Index: 12, Name: "OpenVPN TAP", Description: "TAP-Windows Adapter V9", Hardware: true, Up: true, Gateway: true, Metric: 3}
	all := []Adapter{tun, radmin, eth, vmnet, wifi, tap}

	got := Classify(all, tun.Index)
	if !got.Tunnel || got.Physical.Index != eth.Index || got.Default.Index != tun.Index {
		t.Fatalf("туннель по умолчанию: %+v", got)
	}
	if got := Classify(all, tap.Index); !got.Tunnel || got.Physical.Index != eth.Index {
		t.Fatalf("TAP-адаптер с шлюзом должен считаться туннелем: %+v", got)
	}
	if got := Classify(all, eth.Index); got.Tunnel {
		t.Fatalf("прямой маршрут принят за туннель: %+v", got)
	}
	if got := Classify(all, wifi.Index); got.Tunnel {
		t.Fatalf("второй физический адаптер принят за туннель: %+v", got)
	}
	if got := Classify([]Adapter{tun, radmin}, tun.Index); got.Tunnel {
		t.Fatalf("без физического адаптера привязывать не к чему: %+v", got)
	}
	if got := Classify(all, 0); got.Tunnel {
		t.Fatalf("неизвестный маршрут принят за туннель: %+v", got)
	}
}
