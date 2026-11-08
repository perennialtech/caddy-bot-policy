package botpolicy

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/oschwald/maxminddb-golang/v2"
	"go.uber.org/zap"
)

// The pool keeps one watcher per file across Caddy config reloads.
var asnDatabases = caddy.NewUsagePool()

type asnDatabase struct {
	path    string
	logger  *zap.Logger
	reader  atomic.Pointer[maxminddb.Reader]
	modTime time.Time
	size    int64
	stop    chan struct{}
	done    chan struct{}
}

func newASNDatabase(path string, logger *zap.Logger) (*asnDatabase, error) {
	db := &asnDatabase{
		path:   path,
		logger: logger,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	if err := db.refresh(); err != nil {
		return nil, err
	}
	go db.watch(time.Minute)
	return db, nil
}

// refresh replaces the in-memory reader only after the new file is valid.
func (db *asnDatabase) refresh() error {
	info, err := os.Stat(db.path)
	if err != nil {
		return fmt.Errorf("bot_policy: stat asn_db %q: %w", db.path, err)
	}
	if db.reader.Load() != nil && info.ModTime().Equal(db.modTime) && info.Size() == db.size {
		return nil
	}
	data, err := os.ReadFile(db.path)
	if err != nil {
		return fmt.Errorf("bot_policy: read asn_db %q: %w", db.path, err)
	}
	// In-memory readers remain valid for requests already using the old one.
	reader, err := maxminddb.OpenBytes(data)
	if err != nil {
		return fmt.Errorf("bot_policy: open asn_db %q: %w", db.path, err)
	}
	if reader.Metadata.DatabaseType != "GeoLite2-ASN" && reader.Metadata.DatabaseType != "GeoIP2-ASN" && !strings.Contains(reader.Metadata.DatabaseType, "compat=GeoLite2-ASN") {
		return fmt.Errorf("bot_policy: asn_db %q is not a compatible ASN database", db.path)
	}
	db.reader.Store(reader)
	db.modTime = info.ModTime()
	db.size = info.Size()
	return nil
}

func (db *asnDatabase) watch(interval time.Duration) {
	defer close(db.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := db.refresh(); err != nil {
				db.logger.Warn("ASN database refresh failed; keeping last valid database", zap.Error(err))
			}
		case <-db.stop:
			return
		}
	}
}

func (db *asnDatabase) Destruct() error {
	close(db.stop)
	<-db.done
	return nil
}
