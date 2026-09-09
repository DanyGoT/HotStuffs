package replica

import (
	"bytes"
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DanyGoT/HotStuffs/crypto"
)

func TestNoCommandsPollsEmpty(t *testing.T) {
	cmds, ok := NoCommands{}.Poll()
	if cmds != nil || ok {
		t.Errorf("Poll() = (%v, %v), want (nil, false)", cmds, ok)
	}
}

func TestPayloadUnthrottled(t *testing.T) {
	const size, batch = 32, 4
	p := NewPayload(size, batch, 0)
	for i := range 5 {
		cmds, ok := p.Poll()
		if !ok {
			t.Fatalf("call %d: ok = false, want true", i)
		}
		if len(cmds) != batch {
			t.Fatalf("call %d: len(cmds) = %d, want %d", i, len(cmds), batch)
		}
		for _, c := range cmds {
			if len(c) != size {
				t.Errorf("call %d: command length = %d, want %d", i, len(c), size)
			}
		}
	}
}

func TestPayloadClampsSizeAndBatch(t *testing.T) {
	p := NewPayload(0, 0, 0)
	cmds, ok := p.Poll()
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if len(cmds) != 1 {
		t.Fatalf("len(cmds) = %d, want 1", len(cmds))
	}
	if len(cmds[0]) != 1 {
		t.Fatalf("command length = %d, want 1", len(cmds[0]))
	}
}

// TestPayloadThrottled bounds how much a throttled Payload can hand out over a
// measured interval. Only an upper bound is checked: a lower bound would tie
// the assertion to scheduler timing, which is exactly how this test would
// flake.
func TestPayloadThrottled(t *testing.T) {
	const rate = 200 // commands/sec
	p := NewPayload(8, 1000, rate)

	start := time.Now()
	deadline := start.Add(150 * time.Millisecond)
	total := 0
	for time.Now().Before(deadline) {
		if cmds, ok := p.Poll(); ok {
			total += len(cmds)
		}
	}
	elapsed := time.Since(start)

	// +2 covers int() truncation of the credit and the gap between the last
	// Poll and the elapsed measurement.
	max := int(elapsed.Seconds()*rate) + 2
	if total > max {
		t.Errorf("throttled Poll handed out %d commands over %v at rate %d/s, want <= %d", total, elapsed, rate, max)
	}
}

// TestPayloadCommandsAreUniform checks that every command in one Poll shares
// the same length and content, by value rather than pointer identity.
func TestPayloadCommandsAreUniform(t *testing.T) {
	p := NewPayload(16, 5, 0)
	cmds, ok := p.Poll()
	if !ok {
		t.Fatal("ok = false, want true")
	}
	for i, c := range cmds {
		if len(c) != len(cmds[0]) {
			t.Errorf("command %d: length = %d, want %d", i, len(c), len(cmds[0]))
		}
		if !bytes.Equal(c, cmds[0]) {
			t.Errorf("command %d: content differs from command 0", i)
		}
	}
}

// privBytes and pubBytes are a key's encoded form; Bytes errors only for a key
// that was never valid.
func privBytes(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := k.Bytes()
	if err != nil {
		t.Fatalf("PrivateKey.Bytes: %v", err)
	}
	return b
}

func pubBytes(t *testing.T, k *ecdsa.PublicKey) []byte {
	t.Helper()
	b, err := k.Bytes()
	if err != nil {
		t.Fatalf("PublicKey.Bytes: %v", err)
	}
	return b
}

// TestKeysRoundTrip writes a cluster's key material and reads it back per ID,
// checking both the private key and the full public key set.
func TestKeysRoundTrip(t *testing.T) {
	const n = 4
	privs, pubs, err := crypto.GenerateKeys(n)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}

	dir := t.TempDir()
	if err := crypto.WriteKeys(dir, privs); err != nil {
		t.Fatalf("WriteKeys: %v", err)
	}

	for id, want := range privs {
		priv, allPubs, err := crypto.ReadKeys(dir, id)
		if err != nil {
			t.Fatalf("ReadKeys(%d): %v", id, err)
		}
		if !bytes.Equal(privBytes(t, priv), privBytes(t, want)) {
			t.Errorf("replica %d: private key differs", id)
		}
		if !bytes.Equal(pubBytes(t, &priv.PublicKey), pubBytes(t, &want.PublicKey)) {
			t.Errorf("replica %d: public key differs", id)
		}
		if len(allPubs) != n {
			t.Errorf("replica %d: got %d public keys, want %d", id, len(allPubs), n)
		}
		for pid, wantPub := range pubs {
			got, ok := allPubs[pid]
			if !ok {
				t.Errorf("replica %d: missing public key for %d", id, pid)
				continue
			}
			if !bytes.Equal(pubBytes(t, got), pubBytes(t, wantPub)) {
				t.Errorf("replica %d: public key for %d differs", id, pid)
			}
		}
	}
}

// TestReadKeysFails checks that malformed key directories fail cleanly
// rather than panic.
func TestReadKeysFails(t *testing.T) {
	t.Run("missing directory", func(t *testing.T) {
		if _, _, err := crypto.ReadKeys(filepath.Join(t.TempDir(), "does-not-exist"), 1); err == nil {
			t.Error("got nil error, want non-nil")
		}
	})

	t.Run("no public keys", func(t *testing.T) {
		dir := t.TempDir()
		privs, _, err := crypto.GenerateKeys(1)
		if err != nil {
			t.Fatalf("GenerateKeys: %v", err)
		}
		if err := crypto.WriteKeys(dir, privs); err != nil {
			t.Fatalf("WriteKeys: %v", err)
		}
		if err := os.Remove(filepath.Join(dir, "1.pub")); err != nil {
			t.Fatalf("remove .pub: %v", err)
		}
		if _, _, err := crypto.ReadKeys(dir, 1); err == nil {
			t.Error("got nil error, want non-nil")
		}
	})

	t.Run("pub file name is not a number", func(t *testing.T) {
		dir := t.TempDir()
		privs, _, err := crypto.GenerateKeys(1)
		if err != nil {
			t.Fatalf("GenerateKeys: %v", err)
		}
		if err := crypto.WriteKeys(dir, privs); err != nil {
			t.Fatalf("WriteKeys: %v", err)
		}
		if err := os.Rename(filepath.Join(dir, "1.pub"), filepath.Join(dir, "x.pub")); err != nil {
			t.Fatalf("rename: %v", err)
		}
		if _, _, err := crypto.ReadKeys(dir, 1); err == nil {
			t.Error("got nil error, want non-nil")
		}
	})
}
