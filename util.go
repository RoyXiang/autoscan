package autoscan

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
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

func RCloneForget(directories map[string]struct{}) {
	args := []string{"rc", "vfs/forget"}

	number := 1
	for dir := range directories {
		target := dir
		for {
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				target = dir
				dir = filepath.Clean(filepath.Join(dir, ".."))
				continue
			}
			break
		}
		args = append(args, fmt.Sprintf("dir%d=%s", number, target))
		number++
	}

	cmd := exec.Command("rclone", args...)
	_ = cmd.Run()
}
