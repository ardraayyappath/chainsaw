package ssh

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// RemoteFileInfo holds metadata about a file on the target machine,
// collected via stat. No file contents are included.
type RemoteFileInfo struct {
	Path    string
	Size    int64
	ModTime time.Time
}

// RemoteReader provides read-only access to the filesystem of the target machine.
//
// HARD CONSTRAINT: no method in this file may write to, modify, or delete
// anything on the target. Every operation must be strictly read-only.
// Violating this corrupts mtimes and other evidence.
type RemoteReader struct {
	conn *RemoteConnector
}

// NewRemoteReader wraps a RemoteConnector with read-only filesystem access.
func NewRemoteReader(c *RemoteConnector) *RemoteReader {
	return &RemoteReader{conn: c}
}

// ReadFile returns the contents of a file on the target via `cat`.
// No temporary files are created on the target.
func (r *RemoteReader) ReadFile(path string) ([]byte, error) {
	// Use -- to guard against paths that could be misinterpreted as flags.
	out, err := r.RunCommand(fmt.Sprintf("cat -- %s", shellQuote(path)))
	if err != nil {
		return nil, fmt.Errorf("read file %q on %s: %w", path, r.conn.target, err)
	}
	return out, nil
}

// Glob returns the list of paths on the target that match the given glob pattern.
// Implemented via `find` with -name matching; no writes to target.
//
// The pattern follows standard shell glob syntax (*, ?).
// Results are newline-separated absolute paths.
//
// Note: uses find -name (filename only, not full path) combined with a root
// derived from the non-wildcard prefix. This avoids relying on find -path's
// inconsistent behaviour with '/' in '*' across GNU and BSD find versions.
func (r *RemoteReader) Glob(pattern string) ([]string, error) {
	root := globRoot(pattern)
	// The filename pattern is the last path component of the original pattern.
	// For patterns like "/home/user/*.log", namePattern is "*.log".
	namePattern := filepath.Base(pattern)

	cmd := fmt.Sprintf(
		"find %s -name %s -not -type d 2>/dev/null",
		shellQuote(root),
		shellQuote(namePattern),
	)
	out, err := r.RunCommand(cmd)
	raw := strings.TrimSpace(string(out))
	if err != nil && raw == "" {
		// Root path doesn't exist or is fully inaccessible — not an error for
		// forensic collection; treat as empty result.
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("glob %q on %s: %w", pattern, r.conn.target, err)
	}
	if raw == "" {
		return nil, nil
	}
	return strings.Split(raw, "\n"), nil
}

// FindByName searches for files matching a filename pattern under root, down to
// maxDepth directory levels. pruneDirs lists directory names to skip entirely
// (e.g. "node_modules") — pass nil to skip nothing.
//
// Uses "-type d -name DIR -prune -o" form rather than \(...\) grouping to
// avoid backslash-escaping issues when the command is sent through an SSH session.
func (r *RemoteReader) FindByName(root, namePattern string, maxDepth int, pruneDirs ...string) ([]string, error) {
	// Each prune clause: "-type d -name 'dir' -prune -o"
	// find evaluates left-to-right with short-circuit: if the file is a
	// directory named dir it is pruned (not descended), otherwise the rest
	// of the expression is evaluated.
	prune := ""
	for _, dir := range pruneDirs {
		prune += fmt.Sprintf("-type d -name %s -prune -o ", shellQuote(dir))
	}
	cmd := fmt.Sprintf(
		"find %s -maxdepth %d %s-name %s -not -type d -print 2>/dev/null",
		shellQuote(root), maxDepth, prune, shellQuote(namePattern),
	)
	out, err := r.RunCommand(cmd)
	raw := strings.TrimSpace(string(out))
	if err != nil && raw == "" {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find %q -name %q on %s: %w", root, namePattern, r.conn.target, err)
	}
	if raw == "" {
		return nil, nil
	}
	return strings.Split(raw, "\n"), nil
}

// FindAtDepth finds files exactly minDepth..maxDepth levels deep under root.
// Useful for fixed-structure directories like npm _cacache/index-v5.
func (r *RemoteReader) FindAtDepth(root string, minDepth, maxDepth int) ([]string, error) {
	cmd := fmt.Sprintf(
		"find %s -mindepth %d -maxdepth %d -type f 2>/dev/null",
		shellQuote(root), minDepth, maxDepth,
	)
	out, err := r.RunCommand(cmd)
	raw := strings.TrimSpace(string(out))
	if err != nil && raw == "" {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find %q depth %d-%d on %s: %w", root, minDepth, maxDepth, r.conn.target, err)
	}
	if raw == "" {
		return nil, nil
	}
	return strings.Split(raw, "\n"), nil
}

// Stat returns metadata for a single file on the target via `stat -c`.
// The format string requests: size (%s), modification time as Unix epoch (%Y), name (%n).
// No access-time update occurs because we never open the file for reading here.
func (r *RemoteReader) Stat(path string) (RemoteFileInfo, error) {
	// %s = size in bytes, %Y = mtime as seconds since epoch, %n = file name
	cmd := fmt.Sprintf("stat -c '%%s %%Y %%n' -- %s", shellQuote(path))
	out, err := r.RunCommand(cmd)
	if err != nil {
		return RemoteFileInfo{}, fmt.Errorf("stat %q on %s: %w", path, r.conn.target, err)
	}

	line := strings.TrimSpace(string(out))
	// Expected format: "<size> <epoch> <path>"
	// Split into at most 3 parts so paths with spaces are preserved.
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return RemoteFileInfo{}, fmt.Errorf("stat %q: unexpected output %q", path, line)
	}

	size, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return RemoteFileInfo{}, fmt.Errorf("stat %q: parse size %q: %w", path, parts[0], err)
	}
	epoch, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return RemoteFileInfo{}, fmt.Errorf("stat %q: parse mtime %q: %w", path, parts[1], err)
	}

	return RemoteFileInfo{
		Path:    parts[2],
		Size:    size,
		ModTime: time.Unix(epoch, 0).UTC(),
	}, nil
}

// ResolveHome returns the absolute home directory path on the target machine
// by running `echo "$HOME"`. Use the result as targetHome instead of "~" so
// that paths passed to find/cat/stat are never left with an unexpanded tilde.
func (r *RemoteReader) ResolveHome() (string, error) {
	out, err := r.RunCommand(`echo "$HOME"`)
	if err != nil {
		return "", fmt.Errorf("resolve remote home: %w", err)
	}
	home := strings.TrimSpace(string(out))
	if home == "" {
		return "", fmt.Errorf("remote $HOME is empty")
	}
	return home, nil
}

// RunCommand executes an arbitrary command on the target and returns its combined
// stdout output. stderr is discarded to avoid polluting artifact content.
//
// Callers within this package must only pass read-only commands. This method is
// exported so collectors can issue targeted read commands (e.g. `npm ls --json`)
// that don't fit the ReadFile/Glob/Stat abstractions.
func (r *RemoteReader) RunCommand(cmd string) ([]byte, error) {
	sess, err := r.conn.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new ssh session on %s: %w", r.conn.target, err)
	}
	defer sess.Close()

	var stdout bytes.Buffer
	sess.Stdout = &stdout
	// stderr intentionally not captured — we don't want permission-denied
	// messages from traversing directories to pollute artifact content.

	if err := sess.Run(cmd); err != nil {
		// Return stdout alongside the error so callers can use any output
		// that was produced before the process exited non-zero. This matters
		// for find commands where exit 1 means "root path missing or
		// permission denied on a subdirectory" — both cases may still yield
		// useful partial output.
		return stdout.Bytes(), fmt.Errorf("run %q on %s: %w", cmd, r.conn.target, err)
	}
	return stdout.Bytes(), nil
}

// shellQuote wraps a string in single quotes and escapes any embedded single quotes.
// This is the minimal safe quoting needed when interpolating paths into shell commands.
func shellQuote(s string) string {
	// Replace each ' with '"'"' (end quote, literal quote, re-open quote).
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// globRoot returns the longest path prefix of a glob pattern that contains no
// wildcard characters. Used as the `find` search root.
func globRoot(pattern string) string {
	// filepath.Dir of the pattern up to the first wildcard component.
	parts := strings.Split(pattern, "/")
	var safe []string
	for _, p := range parts {
		if strings.ContainsAny(p, "*?[") {
			break
		}
		safe = append(safe, p)
	}
	if len(safe) == 0 {
		return "/"
	}
	root := filepath.Join(safe...)
	if strings.HasPrefix(pattern, "/") {
		root = "/" + root
	}
	return root
}
