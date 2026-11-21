//go:build windows

package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWindowsStartupTaskRegistration(t *testing.T) {
	if os.Getenv("EVASION_WINDOWS_TASK_TEST") != "1" {
		t.Skip("explicit Windows Task Scheduler integration test")
	}
	_, sid, err := startupTaskIdentity()
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("Evasion-Startup-Test-%d-%d", os.Getpid(), time.Now().UnixNano())
	marker := filepath.Join(t.TempDir(), "started.txt")
	document, err := startupTaskXML(os.Getenv("COMSPEC"), sid)
	if err != nil {
		t.Fatal(err)
	}
	var arguments strings.Builder
	_ = xml.EscapeText(&arguments, []byte(`/c echo Evasion-startup-ok > "`+marker+`"`))
	document = strings.Replace(document, "<Arguments>--autostart</Arguments>", "<Arguments>"+arguments.String()+"</Arguments>", 1)
	path := filepath.Join(t.TempDir(), "startup.xml")
	if err := os.WriteFile(path, startupTaskFile(document), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := taskCommand("/Create", "/TN", name, "/XML", path, "/F"); err != nil {
		t.Fatalf("register task: %v\n%s", err, output)
	}
	t.Cleanup(func() {
		if output, err := taskCommand("/Delete", "/TN", name, "/F"); err != nil {
			t.Errorf("remove isolated test task: %v\n%s", err, output)
		}
	})
	if output, err := taskCommand("/Run", "/TN", name); err != nil {
		t.Fatalf("run task: %v\n%s", err, output)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if b, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(b)) == "Evasion-startup-ok" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Windows registered the task but did not execute its action")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if output, err := taskCommand("/Query", "/TN", name, "/XML"); err != nil {
		t.Fatalf("query task: %v\n%s", err, output)
	} else if enabled, err := taskEnabledXML(output); err != nil || !enabled {
		t.Fatalf("registered task disabled: %v %v", enabled, err)
	}
}
