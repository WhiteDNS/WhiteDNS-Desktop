package main

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestTransferRejectsShortOrCorruptPayload(t *testing.T) {
	for _, data := range []string{"aaaa", "aaaaaaab"} {
		t.Run(data, func(t *testing.T) {
			reader, writer := net.Pipe()
			defer reader.Close()
			go func() { defer writer.Close(); _, _ = writer.Write([]byte(data)) }()
			_, err := transfer(context.Background(), "recv", reader, 8, 8, 0)
			if err == nil {
				t.Fatal("incomplete or corrupt payload accepted")
			}
			if len(data) < 8 && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestUploadWaitsForCompleteAcknowledgement(t *testing.T) {
	for _, ack := range []string{"OK", "O", "NO"} {
		t.Run(ack, func(t *testing.T) {
			sender, receiver := net.Pipe()
			defer sender.Close()
			go func() {
				defer receiver.Close()
				_, _ = io.CopyN(io.Discard, receiver, 8)
				time.Sleep(40 * time.Millisecond)
				for _, b := range []byte(ack) {
					_, _ = receiver.Write([]byte{b})
				}
			}()
			result, err := transfer(context.Background(), "send", sender, 8, 8, 0)
			if ack != "OK" {
				if err == nil {
					t.Fatal("invalid acknowledgement accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Bytes != 8 || result.Elapsed < 40*time.Millisecond {
				t.Fatalf("timer excluded receiver acknowledgement: %+v", result)
			}
		})
	}
}
