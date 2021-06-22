package autoscan

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"syscall"

	"github.com/mitchellh/go-ps"
)

const (
	rcloneExecutable = "rclone"
)

func JoinURL(base string, paths ...string) string {
	// credits: https://stackoverflow.com/a/57220413
	p := path.Join(paths...)
	return fmt.Sprintf("%s/%s", strings.TrimRight(base, "/"), strings.TrimLeft(p, "/"))
}

// DSN creates a data source name for use with sql.Open.
func DSN(path string, q url.Values) string {
	u := url.URL{
		Scheme:   "file",
		Path:     path,
		RawQuery: q.Encode(),
	}

	return u.String()
}

func FlushRcloneCache() {
	processes, _ := ps.Processes()
	for _, process := range processes {
		if process.Executable() == rcloneExecutable {
			parentProc, _ := ps.FindProcess(process.PPid())
			if parentProc.Executable() != rcloneExecutable {
				proc, _ := os.FindProcess(process.Pid())
				_ = proc.Signal(syscall.SIGHUP)
			}
		}
	}
}
