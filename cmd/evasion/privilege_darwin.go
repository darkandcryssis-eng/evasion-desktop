//go:build darwin

package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Перехват на macOS требует root, а оболочка работает от пользователя. Права
// не хранятся на диске: по паролю администратора оболочка поднимает посредника
// (`evasion broker`) из копии движка, принадлежащей root. Посредник живёт,
// пока жива оболочка, и запускает движок только для её дочерних процессов.
//
// Движок, запущенный оболочкой без root, передаёт посреднику свои аргументы,
// рабочий каталог и stdin/stdout/stderr и ждёт код выхода — для оболочки он
// выглядит обычным подпроцессом.

const (
	brokerDir   = "/var/run/evasion-broker"
	brokerSock  = brokerDir + "/sock"
	brokerOwner = "EVASION_OWNER"
)

var rootCommands = map[string]bool{
	"run": true, "doctor": true, "cleanup": true,
	"youtube-tune": true, "youtube-probe": true, "youtube-profile": true,
}

type brokerRequest struct {
	Args []string `json:"args"`
	Dir  string   `json:"dir"`
}

func init() {
	if len(os.Args) < 2 {
		return
	}
	if os.Geteuid() == 0 {
		if os.Args[1] == "broker" {
			os.Exit(runBroker(os.Args[2:]))
		}
		restoreOwnership()
		return
	}
	if rootCommands[os.Args[1]] {
		viaBroker()
	}
}

// restoreOwnership возвращает пользователю файлы состояния, которые движок
// создаёт от root в его каталоге данных.
func restoreOwnership() {
	var uid, gid int
	owner := os.Getenv(brokerOwner)
	for i := 0; i < len(owner); i++ {
		if owner[i] == ':' {
			uid, _ = strconv.Atoi(owner[:i])
			gid, _ = strconv.Atoi(owner[i+1:])
		}
	}
	if uid == 0 {
		return
	}
	go func() {
		for {
			chownState(".", uid, gid)
			time.Sleep(2 * time.Second)
		}
	}()
}

// chownState отдаёт пользователю то, что root создал в state. Каталог
// принадлежит пользователю, поэтому обход идёт через os.Root (символические
// ссылки не выводят наружу), а файл с жёсткими ссылками не трогается: иначе
// пользователь подсунул бы ссылку на чужой файл и получил его во владение.
func chownState(dir string, uid, gid int) {
	base, err := os.OpenRoot(dir)
	if err != nil {
		return
	}
	defer base.Close()
	if info, err := base.Stat("."); err != nil || int(info.Sys().(*syscall.Stat_t).Uid) != uid {
		return
	}
	link, err := base.Lstat("state")
	if err != nil || !link.IsDir() {
		return
	}
	root, err := base.OpenRoot("state")
	if err != nil {
		return
	}
	defer root.Close()
	if top, err := root.Stat("."); err != nil || !os.SameFile(link, top) {
		return
	}
	_ = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || !(d.IsDir() || d.Type().IsRegular()) {
			return nil
		}
		f, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return nil
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if ok && st.Uid == 0 && (info.IsDir() || info.Mode().IsRegular() && st.Nlink == 1) {
			_ = f.Chown(uid, gid)
		}
		return nil
	})
}

// viaBroker выполняет команду через посредника и завершает процесс с её кодом.
// Если посредника нет, команда идёт дальше без root и сама сообщит об этом.
func viaBroker() {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: brokerSock, Net: "unix"})
	if err != nil {
		return
	}
	dir, _ := os.Getwd()
	req, _ := json.Marshal(brokerRequest{Args: os.Args[1:], Dir: dir})
	if _, _, err := conn.WriteMsgUnix(req, unix.UnixRights(0, 1, 2), nil); err != nil {
		os.Exit(1)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for range sig {
			_, _ = conn.Write([]byte{'t'})
		}
	}()
	var code [1]byte
	if _, err := conn.Read(code[:]); err != nil {
		os.Exit(1)
	}
	os.Exit(int(code[0]))
}

// runBroker обслуживает одну оболочку (--pid, --uid, --gid) и выходит вместе с ней.
func runBroker(args []string) int {
	opt := map[string]int{}
	for i := 0; i+1 < len(args); i += 2 {
		opt[args[i]], _ = strconv.Atoi(args[i+1])
	}
	app, uid, gid := opt["--pid"], opt["--uid"], opt["--gid"]
	exe, err := os.Executable()
	if app <= 1 || uid <= 0 || err != nil {
		return 2
	}
	_ = os.Remove(brokerSock)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: brokerSock, Net: "unix"})
	if err != nil {
		return 1
	}
	if os.Chown(brokerSock, uid, gid) != nil || os.Chmod(brokerSock, 0o600) != nil {
		return 1
	}
	signal.Ignore(syscall.SIGHUP)

	var (
		mu       sync.Mutex
		children = map[*exec.Cmd]bool{}
	)
	go func() {
		for unix.Kill(app, 0) != unix.ESRCH {
			time.Sleep(500 * time.Millisecond)
		}
		mu.Lock()
		for c := range children {
			_ = c.Process.Kill()
		}
		_ = os.RemoveAll(brokerDir)
		os.Exit(0)
	}()

	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			return 1
		}
		go func() {
			defer conn.Close()
			cmd, err := brokerCommand(conn, exe, app, uid, gid)
			if err != nil {
				_, _ = conn.Write([]byte{126})
				return
			}
			mu.Lock()
			err = cmd.Start()
			if err == nil {
				children[cmd] = true
			}
			mu.Unlock()
			for _, f := range []any{cmd.Stdin, cmd.Stdout, cmd.Stderr} {
				_ = f.(*os.File).Close()
			}
			if err != nil {
				_, _ = conn.Write([]byte{126})
				return
			}
			// Клиент пишет 't' по SIGTERM; закрытое соединение — клиента убили.
			go func() {
				var b [1]byte
				for {
					if _, err := conn.Read(b[:]); err != nil {
						_ = cmd.Process.Kill()
						return
					}
					_ = cmd.Process.Signal(syscall.SIGTERM)
				}
			}()
			code := 0
			if err := cmd.Wait(); err != nil {
				code = 1
				var ee *exec.ExitError
				if errors.As(err, &ee) && ee.ExitCode() > 0 {
					code = ee.ExitCode()
				}
			}
			chownState(cmd.Dir, uid, gid)
			mu.Lock()
			delete(children, cmd)
			mu.Unlock()
			_, _ = conn.Write([]byte{byte(code)})
		}()
	}
}

// brokerCommand проверяет, что запрос пришёл от дочернего процесса оболочки,
// и собирает команду движка с его stdin/stdout/stderr.
func brokerCommand(conn *net.UnixConn, exe string, app, uid, gid int) (*exec.Cmd, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var peerUID, peerPID = -1, -1
	_ = raw.Control(func(fd uintptr) {
		if cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED); err == nil {
			peerUID = int(cred.Uid)
		}
		if pid, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID); err == nil {
			peerPID = pid
		}
	})
	if peerUID != uid || peerPID <= 1 {
		return nil, errors.New("чужой процесс")
	}
	if kp, err := unix.SysctlKinfoProc("kern.proc.pid", peerPID); err != nil || int(kp.Eproc.Ppid) != app {
		return nil, errors.New("чужой процесс")
	}

	buf, oob := make([]byte, 1<<20), make([]byte, unix.CmsgSpace(3*4))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, err
	}
	var fds []int
	if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil {
		for _, m := range msgs {
			if got, err := unix.ParseUnixRights(&m); err == nil {
				fds = append(fds, got...)
			}
		}
	}
	files := make([]*os.File, len(fds))
	for i, fd := range fds {
		files[i] = os.NewFile(uintptr(fd), "")
	}
	var req brokerRequest
	if len(files) != 3 || json.Unmarshal(buf[:n], &req) != nil || len(req.Args) == 0 ||
		!rootCommands[req.Args[0]] || !filepath.IsAbs(req.Dir) {
		for _, f := range files {
			_ = f.Close()
		}
		return nil, errors.New("неверный запрос")
	}
	// Движок пишет состояние в рабочий каталог: он должен быть каталогом пользователя.
	if st, err := os.Lstat(req.Dir); err != nil || !st.IsDir() || int(st.Sys().(*syscall.Stat_t).Uid) != uid {
		for _, f := range files {
			_ = f.Close()
		}
		return nil, errors.New("неверный запрос")
	}
	cmd := exec.Command(exe, req.Args...)
	cmd.Dir = req.Dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = files[0], files[1], files[2]
	cmd.Env = []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/var/empty",
		brokerOwner + "=" + strconv.Itoa(uid) + ":" + strconv.Itoa(gid),
	}
	return cmd, nil
}
