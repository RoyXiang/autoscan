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

func RCloneForget(pathMap map[string]string) {
	args := []string{"rc", "vfs/forget"}

	number := 1
	for absolute, relative := range pathMap {
		target := relative
		isFile := false
		for {
			if info, err := os.Stat(absolute); os.IsNotExist(err) {
				isFile = true
				target = relative
				absolute = filepath.Clean(filepath.Join(absolute, ".."))
				relative = filepath.Clean(filepath.Join(relative, ".."))
			} else if !info.IsDir() {
				isFile = true
			}
			break
		}
		if isFile {
			args = append(args, fmt.Sprintf("file%d=%s", number, target))
		} else {
			args = append(args, fmt.Sprintf("dir%d=%s", number, target))
		}
	}

	cmd := exec.Command("rclone", args...)
	_ = cmd.Run()
}
