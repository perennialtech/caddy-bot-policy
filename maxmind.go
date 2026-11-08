package botpolicy

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/oschwald/maxminddb-golang/v2"
	"go.uber.org/zap"
)

const maxMindASNURL = "https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz"
const maxMindRefreshInterval = 24 * time.Hour

// A variable permits local HTTP servers in tests without contacting MaxMind.
var maxMindDownloadURL = maxMindASNURL

var maxMindDatabases = caddy.NewUsagePool()

// MaxMindASN configures automatic GeoLite2-ASN downloads. Both credentials
// are required; Caddy placeholders (including {env.*}) are expanded at
// provision time.
type MaxMindASN struct {
	AccountID  string `json:"account_id"`
	LicenseKey string `json:"license_key"`
}

type maxMindCredentials struct {
	accountID  string
	licenseKey string
}

type maxMindUser struct {
	owner  *BotPolicy
	creds  maxMindCredentials
	logger *zap.Logger
}

// managedASNDB is shared by config generations that use the same cache path.
// A request loads the current reader once so it stays valid across updates.
type managedASNDB struct {
	path     string
	url      string
	client   *http.Client
	logger   atomic.Pointer[zap.Logger]
	reader   atomic.Pointer[maxminddb.Reader]
	creds    atomic.Value // maxMindCredentials
	usersMu  sync.Mutex
	users    []maxMindUser
	mu       sync.Mutex // serializes refreshes and protects modified
	modified time.Time
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
}

func maxMindCachePath() string {
	return filepath.Join(caddy.AppDataDir(), "bot_policy", "GeoLite2-ASN.mmdb")
}

func acquireMaxMindDB(path string, owner *BotPolicy, cfg MaxMindASN, logger *zap.Logger) (*managedASNDB, error) {
	value, _, err := maxMindDatabases.LoadOrNew(path, func() (caddy.Destructor, error) {
		ctx, cancel := context.WithCancel(context.Background())
		db := &managedASNDB{
			path:   path,
			url:    maxMindDownloadURL,
			client: &http.Client{Timeout: time.Minute},
			ctx:    ctx,
			cancel: cancel,
			done:   make(chan struct{}),
		}
		db.logger.Store(logger)
		db.creds.Store(maxMindCredentials{cfg.AccountID, cfg.LicenseKey})
		if err := db.loadCache(); err != nil {
			// A corrupt cache cannot be served, so recover by downloading.
			if err := db.download(ctx, time.Time{}); err != nil {
				cancel()
				return nil, fmt.Errorf("initialize MaxMind ASN database: %w", err)
			}
		}
		go db.run()
		return db, nil
	})
	if err != nil {
		return nil, err
	}
	db := value.(*managedASNDB)
	db.addUser(owner, cfg, logger)
	return db, nil
}

func (db *managedASNDB) addUser(owner *BotPolicy, cfg MaxMindASN, logger *zap.Logger) {
	db.usersMu.Lock()
	defer db.usersMu.Unlock()
	credentials := maxMindCredentials{cfg.AccountID, cfg.LicenseKey}
	db.users = append(db.users, maxMindUser{owner: owner, creds: credentials, logger: logger})
	db.creds.Store(credentials)
	db.logger.Store(logger)
}

func (db *managedASNDB) removeUser(owner *BotPolicy) {
	db.usersMu.Lock()
	defer db.usersMu.Unlock()
	for i, user := range db.users {
		if user.owner == owner {
			db.users = append(db.users[:i], db.users[i+1:]...)
			break
		}
	}
	// Rejected reloads must not leave the active config using their keys.
	if n := len(db.users); n > 0 {
		db.creds.Store(db.users[n-1].creds)
		db.logger.Store(db.users[n-1].logger)
	}
}

func (db *managedASNDB) loadCache() error {
	data, err := os.ReadFile(db.path)
	if err != nil {
		return err
	}
	reader, err := openASNDatabase(data, true)
	if err != nil {
		return err
	}
	info, err := os.Stat(db.path)
	if err != nil {
		return err
	}
	db.reader.Store(reader)
	db.modified = info.ModTime()
	return nil
}

func openASNDatabase(data []byte, geoliteOnly bool) (*maxminddb.Reader, error) {
	reader, err := maxminddb.OpenBytes(data)
	if err != nil {
		return nil, err
	}
	if reader.Metadata.DatabaseType != "GeoLite2-ASN" && (geoliteOnly || reader.Metadata.DatabaseType != "GeoIP2-ASN") {
		return nil, errors.New("not a supported MaxMind ASN database")
	}
	return reader, nil
}

func (db *managedASNDB) run() {
	defer close(db.done)
	// Startup with an existing cache never blocks on the network.
	if err := db.refresh(db.ctx); err != nil && db.ctx.Err() == nil {
		db.logger.Load().Error("MaxMind ASN refresh failed", zap.Error(err))
	}
	ticker := time.NewTicker(maxMindRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-db.ctx.Done():
			return
		case <-ticker.C:
			if err := db.refresh(db.ctx); err != nil && db.ctx.Err() == nil {
				db.logger.Load().Error("MaxMind ASN refresh failed", zap.Error(err))
			}
		}
	}
}

func (db *managedASNDB) refresh(ctx context.Context) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	resp, err := db.request(ctx, http.MethodHead)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("MaxMind HEAD: HTTP %d", resp.StatusCode)
	}
	modified, err := http.ParseTime(resp.Header.Get("Last-Modified"))
	if err != nil {
		return fmt.Errorf("MaxMind HEAD missing valid Last-Modified: %w", err)
	}
	if !modified.After(db.modified) {
		return nil
	}
	return db.download(ctx, modified)
}

func (db *managedASNDB) request(ctx context.Context, method string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, db.url, nil)
	if err != nil {
		return nil, err
	}
	creds := db.creds.Load().(maxMindCredentials)
	req.SetBasicAuth(creds.accountID, creds.licenseKey)
	return db.client.Do(req)
}

func (db *managedASNDB) download(ctx context.Context, modified time.Time) error {
	resp, err := db.request(ctx, http.MethodGet)
	if err != nil {
		return fmt.Errorf("download MaxMind ASN database: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download MaxMind ASN database: HTTP %d", resp.StatusCode)
	}
	archive, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("read MaxMind archive: %w", err)
	}
	defer archive.Close()

	tarReader := tar.NewReader(archive)
	var data []byte
	for {
		hdr, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read MaxMind archive: %w", err)
		}
		if hdr.Typeflag == tar.TypeReg && path.Base(hdr.Name) == "GeoLite2-ASN.mmdb" {
			data, err = io.ReadAll(tarReader)
			if err != nil {
				return fmt.Errorf("extract MaxMind ASN database: %w", err)
			}
			break
		}
	}
	if data == nil {
		return errors.New("MaxMind archive contains no GeoLite2-ASN.mmdb")
	}
	reader, err := openASNDatabase(data, true)
	if err != nil {
		return fmt.Errorf("invalid downloaded MaxMind ASN database: %w", err)
	}
	if modified.IsZero() {
		if value := resp.Header.Get("Last-Modified"); value != "" {
			modified, _ = http.ParseTime(value)
		}
	}

	if err := os.MkdirAll(filepath.Dir(db.path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(db.path), ".asn-*.mmdb")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if !modified.IsZero() {
		if err = os.Chtimes(tmp.Name(), modified, modified); err != nil {
			return err
		}
	}
	if err = os.Rename(tmp.Name(), db.path); err != nil {
		return err
	}
	// OpenBytes owns the in-memory bytes. Never close an old reader: a
	// request may still be using it after this atomic pointer swap.
	db.reader.Store(reader)
	db.modified = modified
	db.logger.Load().Info("MaxMind ASN database updated", zap.String("path", db.path))
	return nil
}

func (db *managedASNDB) Destruct() error {
	db.cancel()
	<-db.done
	return nil
}
