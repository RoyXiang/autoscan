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

func (p *Processor) Add(scans ...autoscan.Scan) error {
	if len(p.anchors) > 0 {
		// forget rclone VFS cache
		directories := make(map[string]struct{}, len(scans))
		args := make([]string, 0, len(scans))
		for _, scan := range scans {
			if scan.Path == "" {
				continue
			}
			folder, relativePath := scan.Folder, scan.Path
			for {
				if info, err := os.Stat(folder); os.IsNotExist(err) {
					folder = filepath.Clean(filepath.Join(folder, ".."))
					relativePath = filepath.Clean(filepath.Join(relativePath, ".."))
					continue
				} else if !info.IsDir() {
					folder = filepath.Dir(folder)
					relativePath = filepath.Dir(relativePath)
				}
				if _, ok := directories[folder]; !ok {
					directories[folder] = struct{}{}
					args = append(args, relativePath)
				}
				break
			}
		}
		if len(args) > 0 {
			autoscan.RCloneForget(args)
		}
		// check if scans are duplicate
		directories = make(map[string]struct{}, len(scans))
		result := make([]autoscan.Scan, 0, len(scans))
		for _, scan := range scans {
			if info, err := os.Stat(scan.Folder); os.IsNotExist(err) {
				continue
			} else if !info.IsDir() {
				scan.Folder = filepath.Dir(scan.Folder)
			}
			if _, ok := directories[scan.Folder]; ok {
				continue
			}
			directories[scan.Folder] = struct{}{}
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
