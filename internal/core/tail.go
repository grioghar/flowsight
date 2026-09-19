package core

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"syscall"
)

// Tailer reads a growing log file from where it left off, surviving rotation.
//
// The file is read as bytes and split on '\n' so the offset is exact: a
// text-mode reader that replaced invalid UTF-8 would drift. Rotation is
// detected by inode change or shrinkage. A partial last line stays in the
// file and is read next time, once it is complete.
type Tailer struct {
	Path   string
	offset int64
	inode  uint64
	seeded bool
	// StartAtEnd skips history on the first open (default true), so a restart
	// does not replay a day of alerts.
	StartAtEnd bool
	// MaxBytes bounds one read so a burst cannot stall the job.
	MaxBytes int64
}

func NewTailer(path string) *Tailer {
	return &Tailer{Path: path, StartAtEnd: true, MaxBytes: 32 << 20}
}

// Save/Restore let a module persist the position across restarts.
func (t *Tailer) Position() (int64, uint64) { return t.offset, t.inode }
func (t *Tailer) Restore(offset int64, inode uint64) {
	t.offset, t.inode, t.seeded = offset, inode, inode != 0
}

// Lines calls fn for every complete new line. It returns the count read.
func (t *Tailer) Lines(fn func(line []byte)) (int, error) {
	f, err := os.Open(t.Path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	var ino uint64
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		ino = uint64(sys.Ino)
	}
	if !t.seeded {
		t.seeded = true
		t.inode = ino
		if t.StartAtEnd {
			t.offset = st.Size()
			return 0, nil
		}
		t.offset = 0
	}
	if ino != t.inode || st.Size() < t.offset {
		t.inode = ino
		t.offset = 0
	}
	if st.Size() == t.offset {
		return 0, nil
	}
	if _, err := f.Seek(t.offset, io.SeekStart); err != nil {
		return 0, err
	}
	limit := st.Size() - t.offset
	if t.MaxBytes > 0 && limit > t.MaxBytes {
		limit = t.MaxBytes
	}
	r := bufio.NewReaderSize(io.LimitReader(f, limit), 256<<10)
	n := 0
	for {
		line, err := r.ReadBytes('\n')
		if err == nil {
			t.offset += int64(len(line))
			line = bytes.TrimRight(line, "\r\n")
			if len(line) > 0 {
				fn(line)
				n++
			}
			continue
		}
		// EOF with a partial line: leave it for next time.
		break
	}
	return n, nil
}
