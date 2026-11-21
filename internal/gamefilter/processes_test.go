package gamefilter

import "testing"

func TestLauncherDoesNotCountAsGameClient(t *testing.T) {
	selected := map[uint32]string{1: "albion", 2: "albion", 3: "ubisoft", 4: "ubisoft"}
	images := map[uint32]string{1: `C:\Games\AlbionLauncher.exe`, 2: `C:\Games\launch_albion_online.exe`, 3: `C:\Ubisoft\UbisoftConnect.exe`, 4: `C:\Ubisoft\UbisoftConnectWebCore.exe`}
	s := summarizeProcesses(selected, images)
	if len(s) != 2 || s[0].Clients != 0 || s[0].Launchers != 2 || s[1].Clients != 0 || s[1].Helpers != 1 {
		t.Fatal(s)
	}
	selected[5] = "albion"
	images[5] = `C:\Games\Albion-Online.exe`
	s = summarizeProcesses(selected, images)
	if s[0].Clients != 1 {
		t.Fatal(s)
	}
	images[5] = `C:\Games\Albion-Online_BE.exe`
	s = summarizeProcesses(selected, images)
	if s[0].Clients != 1 {
		t.Fatal(s)
	}
}
