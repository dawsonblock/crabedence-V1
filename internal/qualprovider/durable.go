package qualprovider

import (
	"fmt"
	"os"
	"path/filepath"
)

// durableFS is the provider's durable-storage surface. Production uses
// osDurableFS; tests substitute a wrapper that injects EIO/ENOSPC-style
// failures at one named primitive so every crash boundary of the
// two-phase protocol can be exercised deterministically.
type durableFS interface {
	// AppendLine appends one complete record (including its trailing
	// newline) and fsyncs it before returning.
	AppendLine(path string, payload []byte) error
	// ReadFile reads a whole file.
	ReadFile(path string) ([]byte, error)
	// WriteFileAtomic replaces a file's contents atomically: temp
	// write, fsync, rename, parent-directory fsync.
	WriteFileAtomic(path string, data []byte) error
	// WriteTemp creates a scratch file under dir (create, write, fsync,
	// close) and returns its path. The artifact write is decomposed into
	// WriteTemp / Rename / SyncDir so a failure can be injected at each
	// durable step independently.
	WriteTemp(dir, name string, data []byte) (string, error)
	// Rename atomically replaces newpath with oldpath.
	Rename(oldpath, newpath string) error
	// SyncDir fsyncs a directory so a rename inside it is durable.
	SyncDir(dir string) error
	// Lstat describes a path without following a final symlink.
	Lstat(path string) (os.FileInfo, error)
	// ReadArtifact reads one artifact under dir, refusing symlinks and
	// non-regular files.
	ReadArtifact(dir, name string) ([]byte, error)
	// ReadDirNames lists the entries of dir.
	ReadDirNames(dir string) ([]string, error)
	// Remove deletes one file.
	Remove(path string) error
}

// osDurableFS is the real filesystem implementation.
type osDurableFS struct{}

func (osDurableFS) AppendLine(path string, payload []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(payload); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (osDurableFS) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (osDurableFS) WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return syncDir(dir)
}

func (osDurableFS) WriteTemp(dir, name string, data []byte) (string, error) {
	tmp, err := os.CreateTemp(dir, ".tmp-"+name+"-")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	return tmpName, nil
}

func (osDurableFS) Rename(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}

func (osDurableFS) SyncDir(dir string) error {
	return syncDir(dir)
}

func (osDurableFS) Lstat(path string) (os.FileInfo, error) {
	return os.Lstat(path)
}

func (osDurableFS) ReadArtifact(dir, name string) ([]byte, error) {
	if !validArtifactName(name) {
		return nil, fmt.Errorf("invalid artifact name %q", name)
	}
	return readFileNoFollow(filepath.Join(dir, name))
}

func (osDurableFS) ReadDirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}

func (osDurableFS) Remove(path string) error {
	return os.Remove(path)
}

// syncDir fsyncs a directory so a rename inside it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
