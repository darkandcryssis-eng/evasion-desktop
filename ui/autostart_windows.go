//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/sys/windows"
)

func startupTaskIdentity() (name, sid string, err error) {
	u, err := user.Current()
	if err != nil {
		return "", "", err
	}
	return "Evasion-AutoStart-" + u.Uid, u.Uid, nil
}

func taskCommand(args ...string) ([]byte, error) {
	cmd := exec.Command("schtasks.exe", args...)
	hideConsole(cmd)
	b, err := cmd.CombinedOutput()
	if err != nil {
		if detail := taskOutputText(b); detail != "" {
			err = fmt.Errorf("%w: %s", err, detail)
		}
	}
	return b, err
}

func taskOutputText(b []byte) string {
	if utf8.Valid(b) {
		return strings.TrimSpace(string(b))
	}
	units := make([]uint16, len(b))
	// schtasks uses the current Windows OEM code page for redirected errors.
	n, err := windows.MultiByteToWideChar(1, 0, &b[0], int32(len(b)), &units[0], int32(len(units)))
	if err == nil {
		return strings.TrimSpace(string(utf16.Decode(units[:n])))
	}
	return strings.TrimSpace(strings.ToValidUTF8(string(b), "�"))
}

func startupTaskMissing(name string) bool {
	_, err := os.Stat(filepath.Join(os.Getenv("WINDIR"), "System32", "Tasks", name))
	return os.IsNotExist(err)
}

func startupTaskEnabled() (bool, error) {
	name, _, err := startupTaskIdentity()
	if err != nil {
		return false, err
	}
	b, err := taskCommand("/Query", "/TN", name, "/XML")
	if err != nil {
		if startupTaskMissing(name) {
			return false, nil
		}
		return false, fmt.Errorf("не удалось проверить автозапуск: %w", err)
	}
	return taskEnabledXML(b)
}

func setStartupTask(enabled bool, executable string) error {
	name, sid, err := startupTaskIdentity()
	if err != nil {
		return err
	}
	if !enabled {
		if startupTaskMissing(name) {
			return nil
		}
		if _, err := taskCommand("/Delete", "/TN", name, "/F"); err != nil {
			return fmt.Errorf("не удалось отключить автозапуск: %w", err)
		}
		return nil
	}
	document, err := startupTaskXML(executable, sid)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "evasion-startup-*.xml")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(startupTaskFile(document))
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if _, err := taskCommand("/Create", "/TN", name, "/XML", f.Name(), "/F"); err != nil {
		return fmt.Errorf("не удалось включить автозапуск: %w", err)
	}
	return nil
}
