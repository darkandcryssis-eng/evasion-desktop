package gamefilter

import (
	"strings"
)

type ProcessState struct {
	Family    string `json:"family"`
	Launchers int    `json:"launchers"`
	Clients   int    `json:"clients"`
	Helpers   int    `json:"helpers"`
}

func processRole(family, image string) string {
	image = strings.ReplaceAll(strings.ToLower(image), "\\", "/")
	name := image[strings.LastIndex(image, "/")+1:]
	if family == "custom" {
		return "client"
	}
	if family == "albion" {
		switch name {
		case "albion-online.exe", "albion-online_be.exe", "albiononline.exe":
			return "client"
		case "albionlauncher.exe", "albion-online-launcher.exe", "launch_albion_online.exe", "launcher_albion_online.exe":
			return "launcher"
		}
	}
	if family == "ubisoft" {
		switch name {
		case "ubisoftconnect.exe", "ubisoftgamelauncher.exe", "ubisoftgamelauncher64.exe", "upc.exe", "uplay.exe":
			return "launcher"
		}
	}
	return "helper"
}
func summarizeProcesses(selected map[uint32]string, images map[uint32]string) []ProcessState {
	counts := map[string]ProcessState{}
	for pid, family := range selected {
		s := counts[family]
		s.Family = family
		switch processRole(family, images[pid]) {
		case "client":
			s.Clients++
		case "launcher":
			s.Launchers++
		default:
			s.Helpers++
		}
		counts[family] = s
	}
	out := []ProcessState{}
	for _, family := range []string{"albion", "ubisoft", "custom"} {
		if s, ok := counts[family]; ok {
			out = append(out, s)
		}
	}
	return out
}
