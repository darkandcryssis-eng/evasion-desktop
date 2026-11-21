//go:build !windows

package main

import "errors"

type windowsPACSettings struct{}

func (windowsPACSettings) Snapshot() (internetSettings, error) {
	return internetSettings{}, errors.New("PAC Windows недоступен на этой платформе")
}
func (windowsPACSettings) SetAutoConfigURL(string) error {
	return errors.New("PAC Windows недоступен на этой платформе")
}
func (windowsPACSettings) Notify() error {
	return errors.New("PAC Windows недоступен на этой платформе")
}
