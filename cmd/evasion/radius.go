package main

import (
	"net"
	"strings"

	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/ruguard"
)

type allRadiusMatcher struct {
	excluded *config.DomainSet
}

func newAllRadiusMatcher(exclude []string) allRadiusMatcher {
	return allRadiusMatcher{excluded: config.NewDomainSet(exclude)}
}

func (m allRadiusMatcher) Matches(host, sni string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	return !ruguard.IsRussian(host) &&
		!ruguard.IsRussian(sni) &&
		!m.excluded.Matches(host, sni)
}

func applyRadiusOverride(cfg *config.Config, override string) error {
	if override == "" {
		return nil
	}
	mode, err := config.ParseRadiusMode(override)
	if err != nil {
		return err
	}
	cfg.Radius.Mode = mode
	return nil
}
