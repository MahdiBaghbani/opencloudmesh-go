package store_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/store/json"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/store/mirror"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/store/sqlite"
)

// testShare creates a test outgoing share.
func testOutgoingShare() *store.OutgoingShare {
	return &store.OutgoingShare{
		ProviderId:   "test-provider-id",
		WebDAVId:     "test-webdav-id",
		SharedSecret: "super-secret-token",
		LocalPath:    "/path/to/file.txt",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		State:        "pending",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
}

// testIncomingShare creates a test incoming share.
func testIncomingShare() *store.IncomingShare {
	return &store.IncomingShare{
		ShareId:       "test-share-id",
		SendingServer: "sender.com",
		ProviderId:    "remote-provider-id",
		WebDAVId:      "remote-webdav-id",
		SharedSecret:  "received-secret",
		Owner:         "alice@sender.com",
		Sender:        "alice@sender.com",
		ShareWith:     "bob@example.com",
		Name:          "shared-file.txt",
		ResourceType:  "file",
		Permissions:   "read",
		State:         "pending",
		UserId:        "bob",
		CreatedAt:     time.Now().Unix(),
		UpdatedAt:     time.Now().Unix(),
	}
}

// runDriverTests runs the standard test suite against a driver.
func runDriverTests(t *testing.T, driverName string, cfg *store.DriverConfig) {
	ctx := context.Background()

	// Create driver
	driver, err := store.New(cfg)
	if err != nil {
		t.Fatalf("failed to create %s driver: %v", driverName, err)
	}
	defer driver.Close()

	// Init
	if err := driver.Init(ctx); err != nil {
		t.Fatalf("failed to init %s driver: %v", driverName, err)
	}

	// Check driver name
	if driver.Name() != driverName {
		t.Errorf("expected driver name %q, got %q", driverName, driver.Name())
	}

	// Cast to ShareStore
	shareStore, ok := driver.(store.ShareStore)
	if !ok {
		t.Fatalf("%s driver does not implement ShareStore", driverName)
	}

	t.Run("OutgoingShareCRUD", func(t *testing.T) {
		testOutgoingShareCRUD(t, ctx, shareStore)
	})

	t.Run("IncomingShareCRUD", func(t *testing.T) {
		testIncomingShareCRUD(t, ctx, shareStore)
	})

	t.Run("ProviderKeyScopedLookup", func(t *testing.T) {
		testProviderKeyScopedLookup(t, ctx, shareStore)
	})
}

func testOutgoingShareCRUD(t *testing.T, ctx context.Context, s store.ShareStore) {
	share := testOutgoingShare()

	// Create
	if err := s.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("CreateOutgoingShare failed: %v", err)
	}

	// Get by providerId
	got, err := s.GetOutgoingShare(ctx, share.ProviderId)
	if err != nil {
		t.Fatalf("GetOutgoingShare failed: %v", err)
	}
	if got.ProviderId != share.ProviderId {
		t.Errorf("expected providerId %q, got %q", share.ProviderId, got.ProviderId)
	}

	// Get by webdavId
	got, err = s.GetOutgoingShareByWebDAVId(ctx, share.WebDAVId)
	if err != nil {
		t.Fatalf("GetOutgoingShareByWebDAVId failed: %v", err)
	}
	if got.WebDAVId != share.WebDAVId {
		t.Errorf("expected webdavId %q, got %q", share.WebDAVId, got.WebDAVId)
	}

	// Update
	share.State = "accepted"
	if err := s.UpdateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("UpdateOutgoingShare failed: %v", err)
	}
	got, _ = s.GetOutgoingShare(ctx, share.ProviderId)
	if got.State != "accepted" {
		t.Errorf("expected state 'accepted', got %q", got.State)
	}

	// List
	shares, err := s.ListOutgoingShares(ctx)
	if err != nil {
		t.Fatalf("ListOutgoingShares failed: %v", err)
	}
	if len(shares) == 0 {
		t.Error("expected at least one share in list")
	}

	// Delete
	if err := s.DeleteOutgoingShare(ctx, share.ProviderId); err != nil {
		t.Fatalf("DeleteOutgoingShare failed: %v", err)
	}

	// Verify deleted
	_, err = s.GetOutgoingShare(ctx, share.ProviderId)
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func testIncomingShareCRUD(t *testing.T, ctx context.Context, s store.ShareStore) {
	share := testIncomingShare()

	// Create
	if err := s.CreateIncomingShare(ctx, share); err != nil {
		t.Fatalf("CreateIncomingShare failed: %v", err)
	}

	// Get by shareId
	got, err := s.GetIncomingShare(ctx, share.ShareId)
	if err != nil {
		t.Fatalf("GetIncomingShare failed: %v", err)
	}
	if got.ShareId != share.ShareId {
		t.Errorf("expected shareId %q, got %q", share.ShareId, got.ShareId)
	}

	// Get by provider key (sender-scoped)
	got, err = s.GetIncomingShareByProviderKey(ctx, share.SendingServer, share.ProviderId)
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey failed: %v", err)
	}
	if got.ShareId != share.ShareId {
		t.Errorf("expected shareId %q, got %q", share.ShareId, got.ShareId)
	}

	// Update
	share.State = "accepted"
	if err := s.UpdateIncomingShare(ctx, share); err != nil {
		t.Fatalf("UpdateIncomingShare failed: %v", err)
	}

	// List by user
	shares, err := s.ListIncomingShares(ctx, share.UserId)
	if err != nil {
		t.Fatalf("ListIncomingShares failed: %v", err)
	}
	if len(shares) == 0 {
		t.Error("expected at least one share in list")
	}

	// Delete
	if err := s.DeleteIncomingShare(ctx, share.ShareId); err != nil {
		t.Fatalf("DeleteIncomingShare failed: %v", err)
	}
}

func testProviderKeyScopedLookup(t *testing.T, ctx context.Context, s store.ShareStore) {
	// Create two shares with same providerId but different senders
	share1 := testIncomingShare()
	share1.ShareId = "share-1"
	share1.SendingServer = "server1.com"
	share1.ProviderId = "same-provider-id"

	share2 := testIncomingShare()
	share2.ShareId = "share-2"
	share2.SendingServer = "server2.com"
	share2.ProviderId = "same-provider-id" // Same providerId, different sender

	if err := s.CreateIncomingShare(ctx, share1); err != nil {
		t.Fatalf("CreateIncomingShare share1 failed: %v", err)
	}
	if err := s.CreateIncomingShare(ctx, share2); err != nil {
		t.Fatalf("CreateIncomingShare share2 failed: %v", err)
	}

	// Lookup by server1 should return share1
	got, err := s.GetIncomingShareByProviderKey(ctx, "server1.com", "same-provider-id")
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey server1 failed: %v", err)
	}
	if got.ShareId != "share-1" {
		t.Errorf("expected share-1, got %q", got.ShareId)
	}

	// Lookup by server2 should return share2
	got, err = s.GetIncomingShareByProviderKey(ctx, "server2.com", "same-provider-id")
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey server2 failed: %v", err)
	}
	if got.ShareId != "share-2" {
		t.Errorf("expected share-2, got %q", got.ShareId)
	}

	// Cleanup
	s.DeleteIncomingShare(ctx, share1.ShareId)
	s.DeleteIncomingShare(ctx, share2.ShareId)
}

func TestJSONDriver(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-json-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &store.DriverConfig{
		Driver:  "json",
		DataDir: tempDir,
	}

	runDriverTests(t, "json", cfg)

	// Verify JSON files were created
	if _, err := os.Stat(filepath.Join(tempDir, "outgoing_shares.json")); os.IsNotExist(err) {
		t.Log("outgoing_shares.json not created (expected if no shares remain)")
	}
}

func TestJSONDriverAtomicWrite(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-json-atomic-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "json",
		DataDir: tempDir,
	}

	driver, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Init(ctx); err != nil {
		t.Fatal(err)
	}

	shareStore := driver.(store.ShareStore)

	// Create a share
	share := testOutgoingShare()
	if err := shareStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatal(err)
	}
	driver.Close()

	// Reload driver - data should survive
	driver2, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver2.Init(ctx); err != nil {
		t.Fatal(err)
	}
	defer driver2.Close()

	shareStore2 := driver2.(store.ShareStore)
	got, err := shareStore2.GetOutgoingShare(ctx, share.ProviderId)
	if err != nil {
		t.Fatalf("share not found after restart: %v", err)
	}
	if got.ProviderId != share.ProviderId {
		t.Errorf("data corruption: expected %q, got %q", share.ProviderId, got.ProviderId)
	}
}

func TestSQLiteDriver(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-sqlite-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &store.DriverConfig{
		Driver:  "sqlite",
		DataDir: tempDir,
	}

	runDriverTests(t, "sqlite", cfg)

	// Verify database file was created
	if _, err := os.Stat(filepath.Join(tempDir, "ocm.db")); os.IsNotExist(err) {
		t.Error("ocm.db not created")
	}
}

func TestSQLiteDriverSurvivesRestart(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-sqlite-restart-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "sqlite",
		DataDir: tempDir,
	}

	driver, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Init(ctx); err != nil {
		t.Fatal(err)
	}

	shareStore := driver.(store.ShareStore)

	// Create a share
	share := testOutgoingShare()
	if err := shareStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatal(err)
	}
	driver.Close()

	// Reload driver - data should survive
	driver2, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver2.Init(ctx); err != nil {
		t.Fatal(err)
	}
	defer driver2.Close()

	shareStore2 := driver2.(store.ShareStore)
	got, err := shareStore2.GetOutgoingShare(ctx, share.ProviderId)
	if err != nil {
		t.Fatalf("share not found after restart: %v", err)
	}
	if got.ProviderId != share.ProviderId {
		t.Errorf("data corruption: expected %q, got %q", share.ProviderId, got.ProviderId)
	}
}

func TestMirrorDriver(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-mirror-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
		Mirror: store.MirrorConfig{
			IncludeSecrets: false,
			SecretsScope:   []string{},
		},
	}

	runDriverTests(t, "mirror", cfg)

	// Verify both database and mirror files exist
	if _, err := os.Stat(filepath.Join(tempDir, "ocm.db")); os.IsNotExist(err) {
		t.Error("ocm.db not created")
	}
	if _, err := os.Stat(filepath.Join(tempDir, "mirror")); os.IsNotExist(err) {
		t.Error("mirror directory not created")
	}
}

func TestMirrorDriverSecretRedaction(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-mirror-redact-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()

	// Test with secrets DISABLED
	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
		Mirror: store.MirrorConfig{
			IncludeSecrets: false,
			SecretsScope:   []string{},
		},
	}

	driver, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Init(ctx); err != nil {
		t.Fatal(err)
	}

	shareStore := driver.(store.ShareStore)

	// Create a share with a secret
	share := testOutgoingShare()
	share.SharedSecret = "my-secret-value"
	if err := shareStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatal(err)
	}

	// Read the JSON export
	jsonPath := filepath.Join(tempDir, "mirror", "outgoing_shares.json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}

	// Secret should NOT be in the JSON
	if string(data) != "[]" && contains(string(data), "my-secret-value") {
		t.Error("secret was exported to JSON when IncludeSecrets=false")
	}

	driver.Close()
}

func TestMirrorDriverSecretExport(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-mirror-export-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()

	// Test with secrets ENABLED for webdav_shared_secrets
	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
		Mirror: store.MirrorConfig{
			IncludeSecrets: true,
			SecretsScope:   []string{"webdav_shared_secrets"},
		},
	}

	driver, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Init(ctx); err != nil {
		t.Fatal(err)
	}

	shareStore := driver.(store.ShareStore)

	// Create a share with a secret
	share := testOutgoingShare()
	share.SharedSecret = "exported-secret"
	if err := shareStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatal(err)
	}

	// Read the JSON export
	jsonPath := filepath.Join(tempDir, "mirror", "outgoing_shares.json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}

	// Secret SHOULD be in the JSON
	if !contains(string(data), "exported-secret") {
		t.Error("secret was NOT exported to JSON when IncludeSecrets=true and scope allows")
	}

	driver.Close()
}

func TestMirrorNeverReadsJSON(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-mirror-noread-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
	}

	driver, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Init(ctx); err != nil {
		t.Fatal(err)
	}

	shareStore := driver.(store.ShareStore)

	// Create a share
	share := testOutgoingShare()
	if err := shareStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatal(err)
	}
	driver.Close()

	// Corrupt the JSON file
	jsonPath := filepath.Join(tempDir, "mirror", "outgoing_shares.json")
	os.WriteFile(jsonPath, []byte("CORRUPTED"), 0600)

	// Reload driver - should still work because it reads from SQLite, not JSON
	driver2, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver2.Init(ctx); err != nil {
		t.Fatal(err)
	}
	defer driver2.Close()

	shareStore2 := driver2.(store.ShareStore)
	got, err := shareStore2.GetOutgoingShare(ctx, share.ProviderId)
	if err != nil {
		t.Fatalf("mirror driver read from JSON instead of SQLite: %v", err)
	}
	if got.ProviderId != share.ProviderId {
		t.Errorf("data corruption: expected %q, got %q", share.ProviderId, got.ProviderId)
	}
}

func TestDriverRegistry(t *testing.T) {
	drivers := store.AvailableDrivers()
	
	expected := map[string]bool{"json": true, "sqlite": true, "mirror": true}
	for _, d := range drivers {
		if !expected[d] {
			t.Logf("unexpected driver registered: %s", d)
		}
		delete(expected, d)
	}
	
	for d := range expected {
		t.Errorf("expected driver %q not registered", d)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
