//go:build darwin

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// На macOS оболочка запускает движок как setuid-root: перехвату нужны pf, utun
// и BPF. Реальный uid делаем нулевым, иначе /bin/sh и pfctl сбросят права, а
// файлы состояния возвращаем пользователю — оболочка читает их без root.
func init() {
	uid, gid := os.Getuid(), os.Getgid()
	if os.Geteuid() != 0 || uid == 0 {
		return
	}
	if err := syscall.Setuid(0); err != nil {
		return
	}
	go func() {
		for {
			_ = filepath.WalkDir("state", func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if info, err := d.Info(); err == nil {
					if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid == 0 {
						_ = os.Lchown(path, uid, gid)
					}
				}
				return nil
			})
			time.Sleep(2 * time.Second)
		}
	}()
}
