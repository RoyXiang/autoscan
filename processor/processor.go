package processor

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/cloudbox/autoscan"
	"github.com/cloudbox/autoscan/migrate"

	"golang.org/x/sync/errgroup"
)

type Config struct {
	Anchors    []string
	MinimumAge time.Duration

	Db *sql.DB
	Mg *migrate.Migrator
}

func New(c Config) (*Processor, error) {
	store, err := newDatastore(c.Db, c.Mg)
	if err != nil {
		return nil, err
	}

	proc := &Processor{
		anchors:    c.Anchors,
		minimumAge: c.MinimumAge,
		store:      store,
	}
	return proc, nil
}

type Processor struct {
	anchors    []string
	minimumAge time.Duration
	store      *datastore
	processed  int64
}

type ScanInfo struct {
	Exists   bool
	IsFolder bool
}

func (p *Processor) Add(scans ...autoscan.Scan) error {
	if len(p.anchors) > 0 {
		// forget rclone VFS cache
		infoMap := make(map[string]ScanInfo, len(scans))
		uniqueness := make(map[string]struct{}, len(scans))
		argc, argv := 1, make([]string, 0, len(scans))
		for _, scan := range scans {
			if scan.Path == "" {
				continue
			}
			info := ScanInfo{Exists: false, IsFolder: false}
			folder, relativePath, arg := scan.Folder, scan.Path, scan.Path
			for {
				if fileInfo, err := os.Stat(folder); os.IsNotExist(err) {
					arg = relativePath
					folder = filepath.Dir(folder)
					relativePath = filepath.Dir(relativePath)
					continue
				} else if folder == scan.Folder {
					info.Exists, info.IsFolder = true, fileInfo.IsDir()
				}
				infoMap[scan.Folder] = info
				if _, ok := uniqueness[arg]; ok {
					break
				}
				uniqueness[arg] = struct{}{}
				if !info.Exists || info.IsFolder {
					arg = fmt.Sprintf("dir%d=%s", argc, arg)
				} else {
					arg = fmt.Sprintf("file%d=%s", argc, arg)
				}
				argc++
				argv = append(argv, arg)
				break
			}
		}
		if len(argv) > 0 {
			autoscan.RcloneForget(argv)
		}
		// check if scans are duplicate
		uniqueness = make(map[string]struct{}, len(scans))
		result := make([]autoscan.Scan, 0, len(scans))
		for _, scan := range scans {
			if info, ok := infoMap[scan.Folder]; ok {
				if info.Exists {
					if !info.IsFolder {
						scan.Folder = filepath.Dir(scan.Folder)
					}
				} else if fileInfo, err := os.Stat(scan.Folder); os.IsNotExist(err) {
					continue
				} else if !fileInfo.IsDir() {
					scan.Folder = filepath.Dir(scan.Folder)
				}
			}
			if _, ok := uniqueness[scan.Folder]; ok {
				continue
			}
			uniqueness[scan.Folder] = struct{}{}
			result = append(result, scan)
		}
		scans = result
	}
	return p.store.Upsert(scans)
}

// ScansRemaining returns the amount of scans remaining
func (p *Processor) ScansRemaining() (int, error) {
	return p.store.GetScansRemaining()
}

// ScansProcessed returns the amount of scans processed
func (p *Processor) ScansProcessed() int64 {
	return atomic.LoadInt64(&p.processed)
}

// CheckAvailability checks whether all targets are available.
// If one target is not available, the error will return.
func (p *Processor) CheckAvailability(targets []autoscan.Target) error {
	g := new(errgroup.Group)

	for _, target := range targets {
		target := target
		g.Go(func() error {
			return target.Available()
		})
	}

	return g.Wait()
}

func (p *Processor) callTargets(targets []autoscan.Target, scan autoscan.Scan) error {
	g := new(errgroup.Group)

	for _, target := range targets {
		target := target
		g.Go(func() error {
			return target.Scan(scan)
		})
	}

	return g.Wait()
}

func (p *Processor) Process(targets []autoscan.Target) error {
	scan, err := p.store.GetAvailableScan(p.minimumAge)
	if err != nil {
		return err
	}

	// Check whether all anchors are present
	for _, anchor := range p.anchors {
		if !fileExists(anchor) {
			return fmt.Errorf("%s: %w", anchor, autoscan.ErrAnchorUnavailable)
		}
	}

	// Fatal or Target Unavailable -> return original error
	err = p.callTargets(targets, scan)
	if err != nil {
		return err
	}

	err = p.store.Delete(scan)
	if err != nil {
		return err
	}

	atomic.AddInt64(&p.processed, 1)
	return nil
}

var fileExists = func(fileName string) bool {
	info, err := os.Stat(fileName)
	if err != nil {
		return false
	}

	return !info.IsDir()
}
