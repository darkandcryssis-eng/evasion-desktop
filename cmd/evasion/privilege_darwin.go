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
var rootCommands = map[string]bool{
	"run": true, "doctor": true, "cleanup": true,
	"youtube-tune": true, "youtube-probe": true, "youtube-profile": true,
}

func init() {
	uid, gid := os.Getuid(), os.Getgid()
	if os.Geteuid() != 0 || uid == 0 {
		return
	}
	// Root получают только команды, которыми пользуется оболочка; остальные
	// выполняются от пользователя, как если бы бита setuid не было.
	if len(os.Args) < 2 || !rootCommands[os.Args[1]] {
		_ = syscall.Setgid(gid)
		if syscall.Setuid(uid) != nil || os.Geteuid() == 0 {
			os.Exit(1)
		}
		return
	}
	// Окружение принадлежит вызвавшему: с его PATH или HOME дочерние curl и
	// pfctl запускались бы от root из чужих каталогов и с чужими настройками.
	os.Clearenv()
	_ = os.Setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
	_ = os.Setenv("HOME", "/var/empty")
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
