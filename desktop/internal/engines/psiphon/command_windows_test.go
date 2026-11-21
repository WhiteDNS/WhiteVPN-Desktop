package psiphon

import (
	"os/exec"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWorkersAreTiedToTheApp(t *testing.T) {
	cmd := exec.Command("ping", "-n", "30", "127.0.0.1")
	configureCommand(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if err := bindToApp(cmd.Process.Pid); err != nil {
		t.Fatal(err)
	}
	job, _ := appJob()
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(proc)
	var inJob int32
	isProcessInJob := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")
	if ok, _, err := isProcessInJob.Call(uintptr(proc), uintptr(job), uintptr(unsafe.Pointer(&inJob))); ok == 0 || inJob == 0 {
		t.Fatalf("worker not in the app's job (err=%v)", err)
	}
}
