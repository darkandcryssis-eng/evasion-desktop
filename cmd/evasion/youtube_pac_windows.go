//go:build windows

package main

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type windowsPACSettings struct{}

func (windowsPACSettings) Snapshot() (internetSettings, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return internetSettings{}, err
	}
	defer key.Close()
	var settings internetSettings
	settings.AutoConfigURL, _, err = key.GetStringValue("AutoConfigURL")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return settings, err
	}
	proxyEnable, _, err := key.GetIntegerValue("ProxyEnable")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return settings, err
	}
	settings.ProxyEnable = uint32(proxyEnable)
	settings.ProxyServer, _, err = key.GetStringValue("ProxyServer")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return settings, err
	}
	settings.ProxyOverride, _, err = key.GetStringValue("ProxyOverride")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return settings, err
	}
	return settings, nil
}

func (windowsPACSettings) SetAutoConfigURL(url string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if url == "" {
		err = key.DeleteValue("AutoConfigURL")
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	return key.SetStringValue("AutoConfigURL", url)
}

func (windowsPACSettings) Notify() error {
	proc := windows.NewLazySystemDLL("wininet.dll").NewProc("InternetSetOptionW")
	for _, option := range []uintptr{39, 37} {
		result, _, err := proc.Call(0, option, 0, 0)
		if result == 0 {
			return fmt.Errorf("InternetSetOptionW(%d): %w", option, err)
		}
	}
	return nil
}
