package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanyGoT/HotStuffs/hotstuff"
)

// writeCluster puts a fresh n-replica key set in a temporary directory.
func writeCluster(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	privs, _, err := GenerateKeys(n)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	if err := WriteKeys(dir, privs); err != nil {
		t.Fatalf("WriteKeys: %v", err)
	}
	return dir
}

func TestReadKeysRoundTrip(t *testing.T) {
	const n = 4
	dir := writeCluster(t, n)

	priv, pubs, err := ReadKeys(dir, 2)
	if err != nil {
		t.Fatalf("ReadKeys: %v", err)
	}
	if len(pubs) != n {
		t.Errorf("ReadKeys returned %d public keys, want %d", len(pubs), n)
	}
	if !priv.PublicKey.Equal(pubs[2]) {
		t.Error("the private key read does not match the public key registered for the same ID")
	}
}

// TestReadKeysRejectsNonContiguousSet is the guard against a stale <id>.pub:
// the keys found in the directory are the replica set, so a gap in them would
// otherwise change the quorum and the leader rotation without a word.
func TestReadKeysRejectsNonContiguousSet(t *testing.T) {
	dir := writeCluster(t, 4)
	if err := os.Remove(filepath.Join(dir, "3.pub")); err != nil {
		t.Fatalf("remove 3.pub: %v", err)
	}
	// Three keys remain, but they are 1, 2 and 4 rather than 1..3.
	_, _, err := ReadKeys(dir, 1)
	if err == nil {
		t.Fatal("ReadKeys accepted a key set that is not 1..n")
	}
	if !strings.Contains(err.Error(), "3.pub") {
		t.Errorf("ReadKeys error = %q, want it to name the missing 3.pub", err)
	}
}

func TestReadKeysRejectsEmptyDirectory(t *testing.T) {
	if _, _, err := ReadKeys(t.TempDir(), hotstuff.ID(1)); err == nil {
		t.Fatal("ReadKeys on an empty directory returned no error")
	}
}
