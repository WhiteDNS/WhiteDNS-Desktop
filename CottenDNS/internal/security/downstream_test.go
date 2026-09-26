package security

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

func TestDownstreamDirectionAndOverhead(t *testing.T) {
	for method := 1; method <= 5; method++ {
		t.Run(fmt.Sprint(method), func(t *testing.T) {
			sender, _ := NewCodec(method, "shared downstream test key")
			receiver, _ := NewCodec(method, "shared downstream test key")
			plain := []byte("private frame header and payload")
			ciphertext, err := sender.EncryptDownstream(plain)
			if err != nil {
				t.Fatal(err)
			}
			if len(ciphertext) != len(plain)+sender.CiphertextOverhead() {
				t.Fatal("wrong overhead")
			}
			got, err := receiver.DecryptDownstream(ciphertext)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("round trip: %x %v", got, err)
			}
			upstream, err := sender.Encrypt(plain)
			if err != nil {
				t.Fatal(err)
			}
			reflected, err := receiver.DecryptDownstream(upstream)
			if IsAuthenticatedMethod(method) && err == nil {
				t.Fatal("upstream reflection authenticated")
			}
			if bytes.Equal(reflected, plain) {
				t.Fatal("directions share key")
			}
			if IsAuthenticatedMethod(method) {
				ciphertext[len(ciphertext)-1] ^= 1
				if _, err := receiver.DecryptDownstream(ciphertext); err == nil {
					t.Fatal("tamper authenticated")
				}
			}
		})
	}
}

func TestDownstreamCodecConcurrentFirstUse(t *testing.T) {
	codec, _ := NewCodec(5, "concurrent downstream key")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := []byte("message")
			ct, e := codec.EncryptDownstream(p)
			if e != nil {
				t.Error(e)
				return
			}
			got, e := codec.DecryptDownstream(ct)
			if e != nil || !bytes.Equal(got, p) {
				t.Errorf("round trip: %v", e)
			}
		}()
	}
	wg.Wait()
}
