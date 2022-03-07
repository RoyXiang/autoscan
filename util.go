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

func RCloneForget(directories []string) {
	args := make([]string, 0, len(directories)+2)
	args = append(args, "rc", "vfs/forget")

	i := 1
	for _, dir := range directories {
		args = append(args, fmt.Sprintf("dir%d=%s", i, dir))
	}

	cmd := exec.Command("rclone", args...)
	_ = cmd.Run()
}
