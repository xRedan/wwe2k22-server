package backend

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type eventLogger struct {
	path            string
	verbose         bool
	queue           chan map[string]any
	done            chan struct{}
	once, closeOnce sync.Once
	errors          atomic.Uint64
	started         bool
	mu              sync.Mutex
}

func newEventLogger(path string, verbose bool) *eventLogger {
	if path == "-" {
		path = ""
	}
	return &eventLogger{path: path, verbose: verbose, queue: make(chan map[string]any, 128), done: make(chan struct{})}
}
func (l *eventLogger) start() {
	l.once.Do(func() {
		l.mu.Lock()
		l.started = true
		l.mu.Unlock()
		go func() {
			defer close(l.done)
			for event := range l.queue {
				l.write(event)
			}
		}()
	})
}
func (l *eventLogger) event(event map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.started {
		return
	}
	select {
	case l.queue <- event:
	default:
		l.errors.Add(1)
	}
}
func (l *eventLogger) write(event map[string]any) {
	event["time"] = time.Now().Unix()
	raw, e := json.Marshal(event)
	if e != nil {
		l.errors.Add(1)
		return
	}
	raw = append(raw, '\n')
	if l.path != "" {
		if e = os.MkdirAll(filepath.Dir(l.path), 0700); e != nil {
			l.errors.Add(1)
		} else {
			if info, e := os.Stat(l.path); e == nil && info.Size() >= 5*1024*1024 {
				_ = os.Remove(l.path + ".3")
				for i := 2; i >= 1; i-- {
					_ = os.Rename(l.path+"."+strconv.Itoa(i), l.path+"."+strconv.Itoa(i+1))
				}
				_ = os.Rename(l.path, l.path+".1")
			}
			f, e := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if e != nil {
				l.errors.Add(1)
			} else {
				if _, e = f.Write(raw); e != nil {
					l.errors.Add(1)
				}
				f.Close()
			}
		}
	}
	if _, e = os.Stdout.Write(raw); e != nil {
		l.errors.Add(1)
	}
}
func (l *eventLogger) close() {
	if l == nil {
		return
	}
	l.closeOnce.Do(func() {
		l.mu.Lock()
		started := l.started
		l.started = false
		if started {
			close(l.queue)
		}
		l.mu.Unlock()
		if started {
			<-l.done
		}
	})
}
