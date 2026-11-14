//go:build !windows

package approvalssh

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func prepareTest(t *testing.T) (string, string) {
	t.Helper()
	id := strings.Repeat("a", 32)
	var out bytes.Buffer
	if err := Prepare(id, &out); err != nil {
		t.Fatal(err)
	}
	var endpoint prepared
	if err := json.Unmarshal(out.Bytes(), &endpoint); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(filepath.Dir(endpoint.Socket)); err != nil {
			t.Error(err)
		}
	})
	return id, endpoint.Socket
}
func TestRemotePreparationAndCleanup(t *testing.T) {
	id, socket := prepareTest(t)
	if err := checkRemote(id, socket); err != nil {
		t.Fatal(err)
	}
	if err := checkRemote(strings.Repeat("b", 32), socket); err == nil {
		t.Fatal("other session accepted")
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = Cleanup(id, socket); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Dir(socket)); !os.IsNotExist(err) {
		t.Fatalf("directory survived: %v", err)
	}
	if err = Cleanup(id, socket); err != nil {
		t.Fatal("cleanup is not idempotent", err)
	}
}
func TestCleanupRefusesUnexpectedFiles(t *testing.T) {
	id, socket := prepareTest(t)
	if err := os.WriteFile(socket, []byte("valuable"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Cleanup(id, socket); err == nil {
		t.Fatal("removed regular file")
	}
	data, err := os.ReadFile(socket)
	if err != nil || string(data) != "valuable" {
		t.Fatalf("%s %v", data, err)
	}
	if err = os.Remove(socket); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("/tmp", socket); err != nil {
		t.Fatal(err)
	}
	if err = Cleanup(id, socket); err == nil {
		t.Fatal("removed symlink")
	}
}
func TestCleanupRefusesUnsafeDirectory(t *testing.T) {
	id, socket := prepareTest(t)
	if err := os.Chmod(filepath.Dir(socket), 0755); err != nil {
		t.Fatal(err)
	}
	if err := Cleanup(id, socket); err == nil {
		t.Fatal("unsafe directory accepted")
	}
}
func TestSSHInputs(t *testing.T) {
	for _, host := range []string{"", "-F", "host name", "host\ncommand"} {
		if validHost(host) {
			t.Fatalf("accepted %q", host)
		}
	}
	if !validHost("user@configured-alias") {
		t.Fatal("valid target rejected")
	}
	for _, socket := range []string{"/tmp/unrelated/approval.sock", "/tmp/intent-approval-x/../approval.sock", "/tmp/intent-approval-x/other"} {
		if validRemoteSocket(socket) {
			t.Fatalf("accepted %q", socket)
		}
	}
	if quote("a'b") != "'a'\"'\"'b'" {
		t.Fatal("unsafe shell quoting")
	}
}
