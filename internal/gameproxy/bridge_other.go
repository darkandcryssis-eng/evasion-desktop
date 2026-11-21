//go:build !windows

package gameproxy

import (
	"context"
	"errors"
	"github.com/fitting-1c/evasion/internal/capture"
)

var errWindows = errors.New("игровой маршрут доступен только в Windows")

type Owner interface {
	Owns(string, uint16) bool
	OwnsCurrent(string, uint16) bool
}
type Options struct {
	Proxy    string
	TCP, UDP bool
	Owner    Owner
	Observe  func(capture.Packet)
	Opened   func(bool)
	Error    func()
}
type Bridge struct{}

func Start(context.Context, Options) (*Bridge, error) { return nil, errWindows }
func (*Bridge) Close()                                {}
func (*Bridge) Done() <-chan struct{}                 { return nil }
func (*Bridge) Err() error                            { return errWindows }

type Worker struct{ Endpoint string }

func StartWorker(context.Context, string, string) (*Worker, error) { return nil, errWindows }
func StartWorkerWithProbe(context.Context, string, string, string) (*Worker, error) {
	return nil, errWindows
}
func (*Worker) Close()                    {}
func (*Worker) Done() <-chan struct{}     { return nil }
func SaveProfile(string, Profile) error   { return errWindows }
func LoadProfile(string) (Profile, error) { return Profile{}, errWindows }
