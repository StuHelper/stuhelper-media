// Package media owns logical files and business references, independent of providers.
package media

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	storage "github.com/StuHelper/stuhelper-storage"
	"io"
	"regexp"
	"time"
)

var (
	ErrInput       = errors.New("media_invalid_input")
	ErrDenied      = errors.New("media_permission_denied")
	ErrNotFound    = errors.New("media_not_found")
	ErrConflict    = errors.New("media_conflict")
	ErrUnavailable = errors.New("media_unavailable")
	ErrIntegrity   = errors.New("media_integrity_failed")
	ErrType        = errors.New("media_content_type_rejected")
	ErrCapacity    = errors.New("media_capacity_unavailable")
	ErrExpired     = errors.New("media_upload_expired")
)

type Principal = storage.Principal
type Protection = storage.Protection

// Access is trusted persisted context, never an authorization claim from JSON.
type Access struct {
	FileID, VersionID, Purpose string
	Owner                      Principal
	Protection                 Protection
	Reference                  *Reference
}
type Authorizer interface {
	Authorize(context.Context, Principal, string, Access) error
}

// Store is fulfilled by the storage public service. The distinct service actor
// must have explicit grants; end users never inherit those grants.
type Store interface {
	Create(context.Context, Principal, string, storage.CreateRequest) (storage.Status, error)
	Status(context.Context, Principal, string) (storage.Status, error)
	Ingest(context.Context, Principal, string, string, io.Reader) (storage.Status, error)
	Reference(context.Context, Principal, string, string, storage.Reference, bool) (storage.Status, error)
	Delete(context.Context, Principal, string, string, int64) (storage.Status, error)
	ChangeProtection(context.Context, Principal, string, string, int64, Protection) (storage.Status, error)
	Download(context.Context, Principal, string, io.Writer) error
	ReviewDownload(context.Context, Principal, string, io.Writer) error
}
type Profile struct {
	Module       string     `json:"module"`
	Quarantine   Protection `json:"quarantine"`
	Published    Protection `json:"published"`
	AllowedTypes []string   `json:"allowed_types"`
	MaxSize      int64      `json:"max_size"`
}
type Config struct {
	Profiles                                                                        map[string]Profile
	Actor                                                                           Principal
	Clock                                                                           func() time.Time
	UploadTTL, UnreferencedTTL, OperationTimeout                                    time.Duration
	ParallelTransfers, MaxOpenUploads, MaxFilesPerOwner, MaxVersions, MaxReferences int
	MaxAttempts                                                                     int
	MaxArchiveFiles                                                                 int
	MaxArchiveBytes                                                                 int64
}
type File struct {
	ID          string    `json:"id"`
	Owner       Principal `json:"-"`
	Purpose     string    `json:"purpose"`
	Disabled    bool      `json:"disabled"`
	Deleting    bool      `json:"deleting"`
	Revision    int64     `json:"revision"`
	NextVersion int       `json:"-"`
	CreatedAt   time.Time `json:"created_at"`
}
type Version struct {
	Reused          bool      `json:"reused,omitempty"`
	Shared          bool      `json:"-"`
	ReuseSource     string    `json:"-"`
	ReuseObject     string    `json:"-"`
	ID              string    `json:"id"`
	FileID          string    `json:"file_id"`
	Number          int       `json:"number"`
	Revision        int64     `json:"revision"`
	UploadID        string    `json:"upload_id"`
	Filename        string    `json:"filename"`
	ContentType     string    `json:"content_type"`
	Size            int64     `json:"size"`
	SHA256          string    `json:"sha256"`
	State           string    `json:"state"`
	Approved        bool      `json:"approved"`
	ExpiresAt       time.Time `json:"upload_expires_at"`
	RetainUntil     time.Time `json:"retain_until"`
	CleanupComplete bool      `json:"cleanup_complete"`
	ErrorCode       string    `json:"error_code"`
	// Persistence uses Record so internal locations never enter public JSON.
	ObjectID         string      `json:"-"`
	ObjectIssued     bool        `json:"-"`
	TypeValidated    bool        `json:"-"`
	UploadGeneration int64       `json:"-"`
	UploadUntil      time.Time   `json:"-"`
	Profile          Profile     `json:"-"`
	References       []Reference `json:"-"`
}
type Reference struct {
	ID         string `json:"id"`
	FileID     string `json:"file_id"`
	VersionID  string `json:"version_id"`
	Module     string `json:"module"`
	ResourceID string `json:"resource_id"`
	State      string `json:"state"`
	Revision   int64  `json:"revision"`
}
type UploadRequest struct {
	ReuseExisting bool   `json:"reuse_existing,omitempty"`
	FileID        string `json:"file_id,omitempty"`
	Purpose       string `json:"purpose"`
	Filename      string `json:"filename"`
	ContentType   string `json:"content_type"`
	Size          int64  `json:"size"`
	SHA256        string `json:"sha256"`
}
type Binding struct {
	Module     string `json:"module"`
	ResourceID string `json:"resource_id"`
}
type VersionView struct {
	Version
	StorageState string `json:"storage_state"`
	Healthy      int    `json:"healthy"`
	Desired      int    `json:"desired"`
}
type FileView struct {
	File
	Versions []Version `json:"versions"`
}
type FileListing struct {
	File
	Protection Protection
}

type FilePage struct {
	Items      []File `json:"items"`
	NextCursor string `json:"next_cursor"`
}
type ArchiveRequest struct {
	References []string `json:"references"`
}
type ArchiveEntry struct {
	ReferenceID string `json:"reference_id"`
	VersionID   string `json:"version_id"`
	Path        string `json:"path"`
	Filename    string `json:"filename"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
}
type ArchiveManifest struct {
	Entries   []ArchiveEntry `json:"entries"`
	TotalSize int64          `json:"total_size"`
}

type Replay struct {
	Key, Digest string
	Result      json.RawMessage
}
type Job struct {
	VersionID               string
	State                   string
	Generation              int64
	LeaseOwner              string
	LeaseUntil, AvailableAt time.Time
	Attempts                int
	ErrorCode               string
}
type Event struct {
	SpecVersion     string    `json:"specversion"`
	Source          string    `json:"source"`
	DataContentType string    `json:"datacontenttype"`
	Data            EventData `json:"data"`
	ID              string    `json:"id"`
	Type            string    `json:"type"`
	Subject         string    `json:"subject"`
	Revision        int64     `json:"-"`
	Time            time.Time `json:"time"`
	Actor           Principal `json:"-"`
}
type EventData struct {
	Revision int64 `json:"revision"`
}
type Repository interface {
	Transaction(context.Context, func(Transaction) error) error
	Claim(context.Context, string, time.Time, time.Duration) (Job, error)
	PendingEvents(context.Context, int) ([]Event, error)
	AcknowledgeEvent(context.Context, string) error
}
type Transaction interface {
	ReuseCandidates(Principal, UploadRequest) ([]Version, error)
	Lock(string) error
	File(string) (File, error)
	Files(Principal, int, string) ([]FileListing, error)
	SaveFile(File) error
	Version(string) (Version, error)
	Upload(string) (Version, error)
	Reference(string) (Version, Reference, error)
	Versions(string) ([]Version, error)
	ScanVersions(int, string) ([]Version, error)
	SaveVersion(Version) error
	Counts(Principal) (files, open int, err error)
	Replay(string) (Replay, error)
	SaveReplay(Replay) error
	Job(string) (Job, error)
	SaveJob(Job) error
	Event(Event) error
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func idOK(s string) bool { return identifier.MatchString(s) }
func newID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func hash(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func terminal(v Version) bool {
	return v.State == "cancelled" || v.State == "expired" || v.State == "rejected" || v.State == "deleting" || v.State == "deleted"
}
func liveReferences(v Version) int {
	n := 0
	for _, r := range v.References {
		if r.State != "released" {
			n++
		}
	}
	return n
}
func activeReferences(v Version) int {
	n := 0
	for _, r := range v.References {
		if r.State == "active" {
			n++
		}
	}
	return n
}
