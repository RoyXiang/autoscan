package autoscan

import (
	"fmt"
	"net/url"
	"os/exec"
	"path"
	"strings"
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

func RcloneForget(dir string) {
	cmd := exec.Command("rclone", "rc", "vfs/forget", fmt.Sprintf("dir=%s", dir))
	_ = cmd.Run()
}
