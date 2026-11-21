//go:build windows

package gameproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const profileMagic = "EVASION-GAME-ROUTE-1\n"
const xrayHash = "1d9674327972a21afd4c906a7a72bb0856935aa9e0227c87f34f03d11a88bddf"

func protect(data []byte, decrypt bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, errProfile
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	var err error
	if decrypt {
		err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, 1, &out)
	} else {
		err = windows.CryptProtectData(&in, nil, nil, 0, nil, 1, &out)
	}
	if err != nil {
		return nil, errors.New("не удалось защитить или прочитать игровой профиль этого пользователя Windows")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}

func SaveProfile(path string, p Profile) error {
	if _, err := p.Config(10808); err != nil {
		return err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return errProfile
	}
	defer clear(data)
	sealed, err := protect(data, false)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return errors.New("не удалось создать папку игрового профиля")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".game-route-*")
	if err != nil {
		return errors.New("не удалось сохранить игровой профиль")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, err = f.Write(append([]byte(profileMagic), sealed...))
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("не удалось сохранить игровой профиль")
	}
	if os.Rename(tmp, path) != nil {
		return errors.New("не удалось заменить игровой профиль")
	}
	info, _ := json.Marshal(map[string]int{"nodes": len(p.Outbounds)})
	if os.WriteFile(path+".info.json", info, 0600) != nil {
		return errors.New("не удалось сохранить состояние игрового профиля")
	}
	return nil
}

func LoadProfile(path string) (Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return Profile{}, errors.New("игровой профиль не найден")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, profileLimit+1))
	if err != nil || len(data) > profileLimit || !bytes.HasPrefix(data, []byte(profileMagic)) {
		return Profile{}, errProfile
	}
	plain, err := protect(data[len(profileMagic):], true)
	if err != nil {
		return Profile{}, err
	}
	defer clear(plain)
	var p Profile
	if json.Unmarshal(plain, &p) != nil {
		return Profile{}, errProfile
	}
	if _, err = p.Config(10808); err != nil {
		return Profile{}, err
	}
	return p, nil
}

type Worker struct {
	Endpoint string
	cmd      *exec.Cmd
	job      windows.Handle
	done     chan struct{}
	once     sync.Once
}

func (w *Worker) Close() {
	w.once.Do(func() { windows.CloseHandle(w.job); w.cmd.Process.Kill(); <-w.done })
}
func (w *Worker) Done() <-chan struct{} { return w.done }

func StartWorker(ctx context.Context, path, exe string) (*Worker, error) {
	return startWorker(ctx, path, exe, "")
}

func StartWorkerWithProbe(ctx context.Context, path, exe, probeURL string) (*Worker, error) {
	return startWorker(ctx, path, exe, probeURL)
}

func startWorker(ctx context.Context, path, exe, probeURL string) (*Worker, error) {
	p, err := LoadProfile(path)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		return nil, errors.New("компонент игрового маршрута не найден")
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != xrayHash {
		return nil, errors.New("компонент игрового маршрута повреждён: переустановите Evasion")
	}
	b = nil
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("нет свободного локального порта игрового канала")
	}
	endpoint := l.Addr().String()
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	config, err := p.Config(port)
	if probeURL != "" {
		config, err = p.ConfigProbe(port, probeURL)
	}
	if err != nil {
		l.Close()
		return nil, err
	}
	defer clear(config)
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		l.Close()
		return nil, errors.New("не удалось создать защищённый игровой процесс")
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		windows.CloseHandle(job)
		l.Close()
		return nil, errors.New("не удалось настроить завершение игрового процесса")
	}
	cmd := exec.CommandContext(ctx, exe, "run", "-config", "stdin:")
	cmd.Stdin = bytes.NewReader(config)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	l.Close()
	if err = cmd.Start(); err != nil {
		windows.CloseHandle(job)
		return nil, errors.New("не удалось запустить компонент игрового маршрута")
	}
	w := &Worker{Endpoint: endpoint, cmd: cmd, job: job, done: make(chan struct{})}
	go func() { cmd.Wait(); close(w.done) }()
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		w.Close()
		return nil, errors.New("не удалось связать игровой процесс с Evasion")
	}
	err = windows.AssignProcessToJobObject(job, h)
	windows.CloseHandle(h)
	if err != nil {
		w.Close()
		return nil, errors.New("не удалось включить безопасное завершение игрового процесса")
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-w.done:
			w.Close()
			return nil, errors.New("игровой профиль не принят компонентом маршрута")
		case <-ctx.Done():
			w.Close()
			return nil, ctx.Err()
		case <-deadline.C:
			w.Close()
			return nil, errors.New("локальный игровой канал не запустился")
		case <-ticker.C:
			if c, e := net.DialTimeout("tcp", endpoint, 50*time.Millisecond); e == nil {
				c.Close()
				return w, nil
			}
		}
	}
}
