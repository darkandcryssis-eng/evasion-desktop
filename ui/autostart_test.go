package main

import (
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestStartupTaskUsesInteractiveElevatedLogon(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "Evasion & Новый.exe")
	document, err := startupTaskXML(executable, "S-1-5-21-123")
	if err != nil {
		t.Fatal(err)
	}
	var task struct {
		Principal struct {
			User  string `xml:"UserId"`
			Logon string `xml:"LogonType"`
			Level string `xml:"RunLevel"`
		} `xml:"Principals>Principal"`
		Trigger struct {
			User string `xml:"UserId"`
		} `xml:"Triggers>LogonTrigger"`
		Exec struct {
			Command          string
			Arguments        string
			WorkingDirectory string
		} `xml:"Actions>Exec"`
	}
	if err := xml.Unmarshal([]byte(document), &task); err != nil {
		t.Fatal(err)
	}
	if task.Principal.Logon != "InteractiveToken" || task.Principal.Level != "HighestAvailable" || task.Principal.User != task.Trigger.User {
		t.Fatal("task must run in the current user's interactive elevated session")
	}
	if task.Exec.Command != executable || task.Exec.Arguments != "--autostart" || task.Exec.WorkingDirectory != filepath.Dir(executable) {
		t.Fatalf("incorrect action: %+v", task.Exec)
	}
}

func TestStartupTaskRejectsInvalidPaths(t *testing.T) {
	for _, executable := range []string{"relative.exe", "", filepath.Join(t.TempDir(), "x.exe") + "\n"} {
		if _, err := startupTaskXML(executable, "S-1-5-21-123"); err == nil {
			t.Fatalf("accepted %q", executable)
		}
	}
}

func TestLaunchSettingDefaultsAndRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "launch.json")
	s, err := readLaunchSettings(path)
	if err != nil || s.AutoStart {
		t.Fatalf("autostart must default to off: %+v %v", s, err)
	}
	opts := StartOptions{Voice: "badsum", Quic: "block", Observe: true, RestartDiscord: true}
	var tasks []bool
	if err := updateLaunchSettings(path, true, opts, "test.exe", func(enabled bool, _ string) error { tasks = append(tasks, enabled); return nil }); err != nil {
		t.Fatal(err)
	}
	s, err = readLaunchSettings(path)
	if err != nil || !s.AutoStart || s.Options != opts || len(tasks) != 1 || !tasks[0] {
		t.Fatalf("settings not persisted: %+v %v", s, err)
	}
}

func TestLaunchSettingRejectsInvalidOptionsBeforeSystemChange(t *testing.T) {
	called := false
	err := updateLaunchSettings(filepath.Join(t.TempDir(), "launch.json"), true, StartOptions{Voice: "invalid", Quic: "off"}, "test.exe", func(bool, string) error { called = true; return nil })
	if err == nil || called {
		t.Fatal("invalid options must not modify the task")
	}
}

func TestFailedTaskCreationDoesNotSaveEnabledSetting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "launch.json")
	err := updateLaunchSettings(path, true, defaultLaunchSettings().Options, "test.exe", func(bool, string) error { return errors.New("task failed") })
	s, readErr := readLaunchSettings(path)
	if err == nil || readErr != nil || s.AutoStart {
		t.Fatal("failed task creation must not enable autostart")
	}
}

func TestSettingsWriteFailureRollsBackTask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "launch.json")
	if err := os.Mkdir(path+".tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	var tasks []bool
	err := updateLaunchSettings(path, true, defaultLaunchSettings().Options, "test.exe", func(enabled bool, _ string) error { tasks = append(tasks, enabled); return nil })
	if err == nil || len(tasks) != 2 || !tasks[0] || tasks[1] {
		t.Fatalf("task was not rolled back: %v %v", tasks, err)
	}
}

func TestTaskStatusUTF16AndDisabled(t *testing.T) {
	for _, enabled := range []string{"true", "false"} {
		source := `<?xml version="1.0" encoding="UTF-16"?><Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Description>Ветер 🌬</Description></RegistrationInfo><Settings><Enabled>` + enabled + `</Enabled></Settings></Task>`
		for _, big := range []bool{false, true} {
			b := []byte{0xff, 0xfe}
			if big {
				b = []byte{0xfe, 0xff}
			}
			for _, unit := range utf16.Encode([]rune(source)) {
				if big {
					b = append(b, byte(unit>>8), byte(unit))
				} else {
					b = append(b, byte(unit), byte(unit>>8))
				}
			}
			got, err := taskEnabledXML(b)
			if err != nil || got != (enabled == "true") {
				t.Fatalf("status=%v err=%v", got, err)
			}
		}
	}
}

func TestStartupTaskFileHasMatchingUTF16Encoding(t *testing.T) {
	document, err := startupTaskXML(filepath.Join(t.TempDir(), "Evasion Новый 🌬.exe"), "S-1-5-21-123")
	if err != nil {
		t.Fatal(err)
	}
	b := startupTaskFile(document)
	if len(b) < 2 || b[0] != 0xff || b[1] != 0xfe {
		t.Fatal("Task Scheduler file must have a UTF-16LE BOM")
	}
	if enabled, err := taskEnabledXML(b); err != nil || !enabled {
		t.Fatalf("UTF-16 task cannot be parsed: %v %v", enabled, err)
	}
}

func TestCorruptLaunchSettingsAndShutdownAreRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "launch.json")
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLaunchSettings(path); err == nil {
		t.Fatal("corrupt setting accepted")
	}
	a := NewApp()
	a.shuttingDown = true
	if err := a.StartEngine(defaultLaunchSettings().Options); err == nil || !strings.Contains(err.Error(), "закрывается") {
		t.Fatalf("start during shutdown: %v", err)
	}
}
