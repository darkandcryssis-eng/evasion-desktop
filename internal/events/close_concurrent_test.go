package events

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentCloseWaitsForFlush(t *testing.T) {
	for range 40 {
		w, err := Open(Config{Path: filepath.Join(t.TempDir(), "events.jsonl")})
		if err != nil {
			t.Fatal(err)
		}
		w.Enqueue(Event{})
		start := make(chan struct{})
		errs := make(chan error, 64)
		var wg sync.WaitGroup
		for range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs <- w.Close()
				select {
				case <-w.done:
				default:
					errs <- errCloseBeforeFlush{}
				}
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

type errCloseBeforeFlush struct{}

func (errCloseBeforeFlush) Error() string { return "Close returned before flushing" }
