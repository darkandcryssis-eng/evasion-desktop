//go:build !windows

package gamefilter

type Owners struct{}

func NewOwners(Options) *Owners          { return &Owners{} }
func (*Owners) Owns(string, uint16) bool { return false }
func (*Owners) Status() ([]string, string) {
	return []string{}, "игровой фильтр доступен только в Windows"
}

func (*Owners) Filter() string { return "" }

func (*Owners) Capture() Capture { return Capture{} }

func (*Owners) Active() bool { return false }

func (*Owners) Identity(string, uint16) uint32 { return 0 }

func (*Owners) Processes() []ProcessState { return []ProcessState{} }

func (*Owners) OwnsCurrent(string, uint16) bool { return false }

func (*Owners) Changed() <-chan struct{} { return nil }
