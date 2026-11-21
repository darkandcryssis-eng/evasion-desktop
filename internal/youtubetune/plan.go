package youtubetune

import (
	"context"
	"errors"
)

type Result struct {
	Profile  string  `json:"profile"`
	QUIC     string  `json:"quic"`
	TCP      []Score `json:"tcp"`
	Native   Score   `json:"native"`
	Desync   Score   `json:"desync"`
	Verified bool    `json:"verified"`
}

type Measure func(ctx context.Context, profile, mode, protocol string) (Score, error)

func Run(ctx context.Context, measure Measure, phase func(string)) (Result, error) {
	r := Result{TCP: []Score{}}
	check := func(profile, mode, protocol, stage string) (Score, error) {
		if err := ctx.Err(); err != nil {
			return Score{}, err
		}
		phase(stage)
		s, err := measure(ctx, profile, mode, protocol)
		s.Name = profile
		if err == nil {
			err = ctx.Err()
		}
		return s, err
	}
	for _, name := range Profiles {
		s, err := check(name, "off", "tcp", "tcp:"+name)
		if err != nil {
			return r, err
		}
		r.TCP = append(r.TCP, s)
		if s.Reliable() {
			break
		}
	}
	name, tcpOK := ChooseTCP(r.TCP)
	var err error
	r.Native, err = check(name, "off", "h3", "quic:native")
	if err != nil {
		return r, err
	}
	if !r.Native.Reliable() {
		r.Desync, err = check(name, "desync", "h3", "quic:desync")
		if err != nil {
			return r, err
		}
	}
	mode, ok := ChooseQUIC(r.Native, r.Desync, tcpOK)
	if !ok {
		return r, errors.New("не найден подтверждённый вариант; прежние настройки сохранены")
	}
	protocol := "h3"
	if mode == "block" {
		protocol = "tcp"
	}
	verification, err := check(name, mode, protocol, "verify")
	if err != nil {
		return r, err
	}
	if !verification.Reliable() {
		return r, errors.New("повторная проверка не пройдена; настройки не изменены")
	}
	r.Profile, r.QUIC, r.Verified = name, mode, true
	return r, nil
}
