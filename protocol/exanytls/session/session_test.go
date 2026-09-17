package session

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/atomic"
)

func TestConcurrentStreamsAndLargeFrames(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	var clientPadding atomic.TypedValue[*padding.PaddingFactory]
	var serverPadding atomic.TypedValue[*padding.PaddingFactory]
	if !padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &clientPadding) ||
		!padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &serverPadding) {
		t.Fatal("failed to initialize AnyTLS padding")
	}

	server := NewServerSession(serverConn, func(stream *Stream) {
		if err := stream.HandshakeSuccess(); err != nil {
			_ = stream.Close()
			return
		}
		_, _ = io.Copy(stream, stream)
		_ = stream.Close()
	}, &serverPadding, discardLogger{}, Options{})
	defer server.Close()
	serverDone := make(chan struct{})
	go func() {
		server.Run()
		close(serverDone)
	}()
	client := NewClientSession(clientConn, &clientPadding, discardLogger{}, Options{})
	defer client.Close()
	client.Run()

	const streamCount = 16
	errors := make(chan error, streamCount)
	var waitGroup sync.WaitGroup
	for streamIndex := 0; streamIndex < streamCount; streamIndex++ {
		streamIndex := streamIndex
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			stream, err := client.OpenStream()
			if err != nil {
				errors <- err
				return
			}
			defer stream.Close()
			_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte{byte(streamIndex + 1)}, 2*maxFrameDataLen+streamIndex+1)
			writeDone := make(chan error, 1)
			go func() {
				_, writeErr := stream.Write(payload)
				writeDone <- writeErr
			}()
			received := make([]byte, len(payload))
			if _, err = io.ReadFull(stream, received); err != nil {
				errors <- fmt.Errorf("stream %d read: %w", streamIndex, err)
				return
			}
			if err = <-writeDone; err != nil {
				errors <- fmt.Errorf("stream %d write: %w", streamIndex, err)
				return
			}
			if !bytes.Equal(received, payload) {
				errors <- fmt.Errorf("stream %d payload changed", streamIndex)
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		waitGroup.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("concurrent AnyTLS streams did not finish")
	}
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	_ = client.Close()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server session did not close")
	}
}

type discardLogger struct{}

func (discardLogger) Trace(...any) {}
func (discardLogger) Debug(...any) {}
func (discardLogger) Info(...any)  {}
func (discardLogger) Warn(...any)  {}
func (discardLogger) Error(...any) {}
func (discardLogger) Fatal(...any) {}
func (discardLogger) Panic(...any) {}
