//go:build maxexperiment

package soar

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func experimentTestCipher(t testing.TB, name string) *packetCipher {
	t.Helper()
	if err := SetExperimentCipher(name); err != nil {
		t.Fatal(err)
	}
	c, err := newCipher(bytes.Repeat([]byte{0x31}, 32), "up")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestExperimentCipherPackets(t *testing.T) {
	defer SetExperimentCipher("chacha20-poly1305-8")
	for _, suite := range ExperimentCipherNames() {
		t.Run(suite, func(t *testing.T) {
			c := experimentTestCipher(t, suite)
			for _, size := range []int{4, 55, 200, 512, 1200} {
				plain := make([]byte, size)
				if _, err := rand.Read(plain); err != nil {
					t.Fatal(err)
				}
				const pn, upPN = uint64(12345), uint64(94321)
				decode := func(v uint16) uint64 { return uint64(v) }
				up := c.sealUp(0x321, pn, plain)
				gotPN, got, err := c.openUp(up, decode)
				if err != nil || gotPN != pn || !bytes.Equal(got, plain) {
					t.Fatalf("up size %d: pn=%d err=%v", size, gotPN, err)
				}
				if len(up) != 4+size+tagLen {
					t.Fatal("up wire budget does not match selected tag")
				}
				down := c.sealDown(pn, upPN, plain)
				gotPN, got, err = c.openDown(down, upPN, decode)
				if err != nil || gotPN != pn || !bytes.Equal(got, plain) {
					t.Fatalf("down size %d: pn=%d err=%v", size, gotPN, err)
				}
				if len(down) != 2+size+tagLen {
					t.Fatal("down wire budget does not match selected tag")
				}
				if _, _, err = c.openDown(down, upPN+1, decode); err == nil {
					t.Fatal("accepted reply bound to a different query")
				}
				if _, _, err = c.openUp(up, func(v uint16) uint64 { return uint64(v) + 1 }); err == nil {
					t.Fatal("accepted wrong expanded packet number")
				}
				for i := range up {
					corrupt := bytes.Clone(up)
					corrupt[i] ^= 0x80
					if _, _, err = c.openUp(corrupt, decode); err == nil {
						t.Fatalf("accepted modified byte %d of upstream packet", i)
					}
				}
				for i := range down {
					corrupt := bytes.Clone(down)
					corrupt[i] ^= 0x80
					if _, _, err = c.openDown(corrupt, upPN, decode); err == nil {
						t.Fatalf("accepted modified byte %d of downstream packet", i)
					}
				}
				for i := 0; i < len(up); i++ {
					if _, _, err = c.openUp(up[:i], decode); err == nil {
						t.Fatalf("accepted truncated upstream packet length %d", i)
					}
				}
			}
			// The AEAD authenticates packet numbers; the session prevents authenticated
			// packet replay. Exercise both layers rather than claiming AEAD alone dedups.
			s := newSession(true, streamConfig{}, c, c)
			plain := []byte{frPing, frPadding, frPadding, frPadding}
			sealed := c.sealUp(7, 21, plain)
			pn, opened, err := c.openUp(sealed, func(v uint16) uint64 { return uint64(v) })
			if err != nil {
				t.Fatal(err)
			}
			if fresh, err := s.receive(pn, opened, time.Now()); err != nil || !fresh {
				t.Fatalf("first delivery: fresh=%v err=%v", fresh, err)
			}
			if fresh, err := s.receive(pn, opened, time.Now()); err != nil || fresh {
				t.Fatalf("replay: fresh=%v err=%v", fresh, err)
			}
		})
	}
}

func TestExperimentChaChaStackTagWireEquivalence(t *testing.T) {
	defer SetExperimentCipher("chacha20-poly1305-8")
	baseline := experimentTestCipher(t, "chacha20-poly1305-8")
	optimized := experimentTestCipher(t, "chacha20-poly1305-8-stacktag")
	if baseline.key != optimized.key || baseline.iv != optimized.iv || baseline.hp != optimized.hp {
		t.Fatal("optimization changed traffic derivation")
	}
	standard, err := chacha20poly1305.New(baseline.key[:])
	if err != nil {
		t.Fatal(err)
	}
	// Cover every Poly1305 padding boundary, empty AD/plaintext, and larger packets.
	for size := 0; size <= 1232; size++ {
		plain := bytes.Repeat([]byte{byte(size)}, size)
		for _, adLen := range []int{0, 1, 4, 10, 15, 16, 17, 32} {
			ad := bytes.Repeat([]byte{0xc3}, adLen)
			pn := uint64(size*17 + adLen + 1)
			want := standard.Seal(nil, baseline.nonce(pn), plain, ad)
			want = want[:len(want)-8] // original protocol keeps first eight MAC bytes
			got := baseline.seal(nil, ad, plain, pn)
			opt := optimized.seal(nil, ad, plain, pn)
			if !bytes.Equal(got, want) || !bytes.Equal(opt, want) {
				t.Fatalf("vector mismatch size=%d AD=%d", size, adLen)
			}
			opened, err := optimized.open(ad, got, pn)
			if err != nil || !bytes.Equal(opened, plain) {
				t.Fatalf("optimized cannot open baseline: %v", err)
			}
			opened, err = baseline.open(ad, opt, pn)
			if err != nil || !bytes.Equal(opened, plain) {
				t.Fatalf("baseline cannot open optimized: %v", err)
			}
		}
		if size >= 4 {
			if !bytes.Equal(baseline.sealUp(19, uint64(size), plain), optimized.sealUp(19, uint64(size), plain)) {
				t.Fatal("upstream wire changed")
			}
			if !bytes.Equal(baseline.sealDown(uint64(size), 49, plain), optimized.sealDown(uint64(size), 49, plain)) {
				t.Fatal("downstream wire changed")
			}
		}
	}
}

func TestExperimentChaChaStackTagRandomKeys(t *testing.T) {
	defer SetExperimentCipher("chacha20-poly1305-8")
	for trial := 0; trial < 128; trial++ {
		prk := make([]byte, 32)
		if _, err := rand.Read(prk); err != nil {
			t.Fatal(err)
		}
		var ciphers [2]*packetCipher
		for i, suite := range []string{"chacha20-poly1305-8", "chacha20-poly1305-8-stacktag"} {
			if err := SetExperimentCipher(suite); err != nil {
				t.Fatal(err)
			}
			c, err := newCipher(prk, []string{"up", "down"}[trial%2])
			if err != nil {
				t.Fatal(err)
			}
			ciphers[i] = c
		}
		plain := make([]byte, (trial*157)%1233)
		ad := make([]byte, trial%33)
		if _, err := rand.Read(plain); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(ad); err != nil {
			t.Fatal(err)
		}
		pn := uint64(trial)*0x133713371337 + 0x1122334455667788
		baseline := ciphers[0].seal(nil, ad, plain, pn)
		optimized := ciphers[1].seal(nil, ad, plain, pn)
		if !bytes.Equal(baseline, optimized) {
			t.Fatal("random-key optimization changed authenticated ciphertext")
		}
	}
}

func TestExperimentCipherSelection(t *testing.T) {
	defer SetExperimentCipher("chacha20-poly1305-8")
	for _, name := range ExperimentCipherNames() {
		if err := SetExperimentCipher(name); err != nil {
			t.Fatal(err)
		}
		got, size := ExperimentCipherInfo()
		if got != name || size != tagLen || minPlain < 0 || minPlain+tagLen < sampleLen {
			t.Fatal("incorrect selected packet-size budget")
		}
		if err := SetExperimentCipher("not-a-cipher"); err == nil {
			t.Fatal("accepted unknown suite")
		}
		if got, _ := ExperimentCipherInfo(); got != name {
			t.Fatal("invalid selection changed cipher")
		}
	}
}

var experimentPacketSink []byte

// BenchmarkExperimentPacketCrypto includes the actual packet header protection,
// nonce construction, authentication, and allocations used by the tunnel. Bytes
// reported by testing.B are plaintext bytes, not DNS-wire throughput.
func BenchmarkExperimentPacketCrypto(b *testing.B) {
	defer SetExperimentCipher("chacha20-poly1305-8")
	for _, suite := range ExperimentCipherNames() {
		b.Run(suite, func(b *testing.B) {
			c := experimentTestCipher(b, suite)
			for _, size := range []int{55, 200, 512, 1200} {
				b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
					plain := bytes.Repeat([]byte{0x41}, size)
					const packetNumber, queryNumber = uint64(2351), uint64(1943)
					up := c.sealUp(17, packetNumber, plain)
					down := c.sealDown(packetNumber, queryNumber, plain)
					decode := func(v uint16) uint64 { return uint64(v) }
					b.Run("SealUp", func(b *testing.B) {
						b.SetBytes(int64(size))
						b.ReportAllocs()
						pn := uint64(0)
						for b.Loop() {
							experimentPacketSink = c.sealUp(17, pn, plain)
							pn++
						}
					})
					b.Run("OpenUp", func(b *testing.B) {
						b.SetBytes(int64(size))
						b.ReportAllocs()
						for b.Loop() {
							_, p, err := c.openUp(up, decode)
							if err != nil {
								b.Fatal(err)
							}
							experimentPacketSink = p
						}
					})
					b.Run("SealDown", func(b *testing.B) {
						b.SetBytes(int64(size))
						b.ReportAllocs()
						pn := uint64(0)
						for b.Loop() {
							experimentPacketSink = c.sealDown(pn, queryNumber, plain)
							pn++
						}
					})
					b.Run("OpenDown", func(b *testing.B) {
						b.SetBytes(int64(size))
						b.ReportAllocs()
						for b.Loop() {
							_, p, err := c.openDown(down, queryNumber, decode)
							if err != nil {
								b.Fatal(err)
							}
							experimentPacketSink = p
						}
					})
				})
			}
		})
	}
}
