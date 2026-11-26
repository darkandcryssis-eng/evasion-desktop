//go:build !windows && (!darwin || !cgo)

package main

import "context"

func configureWindowCorners(context.Context) {}
