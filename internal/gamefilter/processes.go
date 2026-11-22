package gamefilter

type ProcessState struct {
	Family    string `json:"family"`
	Launchers int    `json:"launchers"`
	Clients   int    `json:"clients"`
	Helpers   int    `json:"helpers"`
}

// Added executables count as clients; processes they started count as helpers.
func summarizeProcesses(selected map[uint32]string, direct map[uint32]bool) []ProcessState {
	if len(selected) == 0 {
		return []ProcessState{}
	}
	s := ProcessState{Family: "custom"}
	for pid := range selected {
		if direct[pid] {
			s.Clients++
		} else {
			s.Helpers++
		}
	}
	return []ProcessState{s}
}
