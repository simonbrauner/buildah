package buildah

import (
	"archive/tar"
	"errors"
	"fmt"
	"hash"
	"io"
	"path"
	"strings"
	"sync"
	"time"

	digest "github.com/opencontainers/go-digest"
)

type tarFilterAction int

const (
	tarFilterKeep  tarFilterAction = iota // write this entry
	tarFilterSkip                         // discard this entry
	tarFilterDefer                        // buffer this entry, emit only if a child survives
)

type digester interface {
	io.WriteCloser
	ContentType() string
	Digest() digest.Digest
}

// A simple digester just digests its content as-is.
type simpleDigester struct {
	digester    digest.Digester
	hasher      hash.Hash
	contentType string
}

func newSimpleDigester(contentType string) digester {
	finalDigester := digest.Canonical.Digester()
	return &simpleDigester{
		digester:    finalDigester,
		hasher:      finalDigester.Hash(),
		contentType: contentType,
	}
}

func (s *simpleDigester) ContentType() string {
	return s.contentType
}

func (s *simpleDigester) Write(p []byte) (int, error) {
	return s.hasher.Write(p)
}

func (s *simpleDigester) Close() error {
	return nil
}

func (s *simpleDigester) Digest() digest.Digest {
	return s.digester.Digest()
}

// A tarFilterer passes a tarball through to an io.WriteCloser, potentially
// modifying headers as it goes.
type tarFilterer struct {
	wg         sync.WaitGroup
	pipeWriter *io.PipeWriter
	closedLock sync.Mutex
	closed     bool
	err        error
}

func (t *tarFilterer) Write(p []byte) (int, error) {
	n, err := t.pipeWriter.Write(p)
	if err != nil {
		t.closedLock.Lock()
		closed := t.closed
		t.closedLock.Unlock()
		err = fmt.Errorf("writing to tar filter pipe (closed=%v,err=%v): %w", closed, t.err, err)
	}
	return n, err
}

func (t *tarFilterer) Close() error {
	t.closedLock.Lock()
	if t.closed {
		t.closedLock.Unlock()
		return errors.New("tar filter is already closed")
	}
	t.closed = true
	t.closedLock.Unlock()
	err := t.pipeWriter.Close()
	t.wg.Wait()
	if err != nil {
		return fmt.Errorf("closing filter pipe: %w", err)
	}
	return t.err
}

// newTarFilterer passes one or more tar archives through to an io.WriteCloser
// as a single archive, potentially calling filter to modify headers and
// contents as it goes.
//
// Note: if "filter" indicates that a given item should be skipped, there is no
// guarantee that there will not be a subsequent item of type TypeLink, which
// is a hard link, which points to the skipped item as the link target.
func newTarFilterer(writeCloser io.WriteCloser, filter func(hdr *tar.Header) (action tarFilterAction, replaceContents bool, replacementContents io.Reader)) io.WriteCloser {
	pipeReader, pipeWriter := io.Pipe()
	tarWriter := tar.NewWriter(writeCloser)
	filterer := &tarFilterer{
		pipeWriter: pipeWriter,
	}
	filterer.wg.Go(func() {
		filterer.closedLock.Lock()
		closed := filterer.closed
		filterer.closedLock.Unlock()
		var deferred []*tar.Header
		for !closed {
			tarReader := tar.NewReader(pipeReader)
			hdr, err := tarReader.Next()
			for err == nil {
				action := tarFilterKeep
				var replaceContents bool
				var replacementContents io.Reader
				if filter != nil {
					action, replaceContents, replacementContents = filter(hdr)
				}
				switch action {
				case tarFilterDefer:
					hdrCopy := *hdr
					deferred = append(deferred, &hdrCopy)
				case tarFilterKeep:
					nameSpec := strings.TrimRight(path.Clean(hdr.Name), "/")
					for i := 0; i < len(deferred); {
						deferredName := strings.TrimRight(path.Clean(deferred[i].Name), "/")
						if strings.HasPrefix(nameSpec, deferredName+"/") {
							if err = tarWriter.WriteHeader(deferred[i]); err != nil {
								err = fmt.Errorf("writing deferred tar header for %q: %w", deferred[i].Name, err)
								break
							}
							if err = tarWriter.Flush(); err != nil {
								err = fmt.Errorf("flushing deferred tar item padding for %q: %w", deferred[i].Name, err)
								break
							}
							deferred = append(deferred[:i], deferred[i+1:]...)
						} else {
							i++
						}
					}
					if err != nil {
						break
					}
					if err = tarWriter.WriteHeader(hdr); err != nil {
						err = fmt.Errorf("writing tar header for %q: %w", hdr.Name, err)
						break
					}
					if hdr.Size != 0 {
						var n int64
						var copyErr error
						if replaceContents {
							n, copyErr = io.CopyN(tarWriter, replacementContents, hdr.Size)
						} else {
							n, copyErr = io.Copy(tarWriter, tarReader)
						}
						if copyErr != nil {
							err = fmt.Errorf("copying content for %q: %w", hdr.Name, copyErr)
							break
						}
						if n != hdr.Size {
							err = fmt.Errorf("filtering content for %q: expected %d bytes, got %d bytes", hdr.Name, hdr.Size, n)
							break
						}
					}
					if err = tarWriter.Flush(); err != nil {
						err = fmt.Errorf("flushing tar item padding for %q: %w", hdr.Name, err)
					}
				}
				hdr, err = tarReader.Next()
			}
			deferred = nil
			if !errors.Is(err, io.EOF) {
				filterer.err = fmt.Errorf("reading tar archive: %w", err)
				break
			}
			filterer.closedLock.Lock()
			closed = filterer.closed
			filterer.closedLock.Unlock()
		}
		err1 := tarWriter.Close()
		err := writeCloser.Close()
		if err == nil {
			err = err1
		}
		if err != nil {
			pipeReader.CloseWithError(err)
		} else {
			pipeReader.Close()
		}
	})
	return filterer
}

// A tar digester digests an archive, modifying the headers it digests by
// calling a specified function to potentially modify the header that it's
// about to write.
type tarDigester struct {
	isOpen      bool
	nested      digester
	tarFilterer io.WriteCloser
}

func modifyTarHeaderForDigesting(hdr *tar.Header) (action tarFilterAction, replaceContents bool, replacementContents io.Reader) {
	zeroTime := time.Time{}
	hdr.ModTime = zeroTime
	hdr.AccessTime = zeroTime
	hdr.ChangeTime = zeroTime
	return tarFilterKeep, false, nil
}

func newTarDigester(contentType string) digester {
	nested := newSimpleDigester(contentType)
	digester := &tarDigester{
		isOpen:      true,
		nested:      nested,
		tarFilterer: newTarFilterer(nested, modifyTarHeaderForDigesting),
	}
	return digester
}

func (t *tarDigester) ContentType() string {
	return t.nested.ContentType()
}

func (t *tarDigester) Digest() digest.Digest {
	return t.nested.Digest()
}

func (t *tarDigester) Write(p []byte) (int, error) {
	return t.tarFilterer.Write(p)
}

func (t *tarDigester) Close() error {
	if t.isOpen {
		t.isOpen = false
		return t.tarFilterer.Close()
	}
	return nil
}

// CompositeDigester can compute a digest over multiple items.
type CompositeDigester struct {
	digesters []digester
	closer    io.Closer
}

// closeOpenDigester closes an open sub-digester, if we have one.
func (c *CompositeDigester) closeOpenDigester() {
	if c.closer != nil {
		c.closer.Close()
		c.closer = nil
	}
}

// Restart clears all state, so that the composite digester can start over.
func (c *CompositeDigester) Restart() {
	c.closeOpenDigester()
	c.digesters = nil
}

// Start starts recording the digest for a new item ("", "file", or "dir").
// The caller should call Hash() immediately after to retrieve the new
// io.WriteCloser.
func (c *CompositeDigester) Start(contentType string) {
	c.closeOpenDigester()
	switch contentType {
	case "":
		c.digesters = append(c.digesters, newSimpleDigester(""))
	case "file", "dir":
		digester := newTarDigester(contentType)
		c.closer = digester
		c.digesters = append(c.digesters, digester)
	default:
		panic(fmt.Sprintf(`unrecognized content type: expected "", "file", or "dir", got %q`, contentType))
	}
}

// Hash returns the hasher for the current item.
func (c *CompositeDigester) Hash() io.WriteCloser {
	num := len(c.digesters)
	if num == 0 {
		return nil
	}
	return c.digesters[num-1]
}

// Digest returns the content type and a composite digest over everything
// that's been digested.
func (c *CompositeDigester) Digest() (string, digest.Digest) {
	c.closeOpenDigester()
	num := len(c.digesters)
	switch num {
	case 0:
		return "", ""
	case 1:
		return c.digesters[0].ContentType(), c.digesters[0].Digest()
	default:
		var content strings.Builder
		for i, digester := range c.digesters {
			if i > 0 {
				content.WriteString(",")
			}
			contentType := digester.ContentType()
			if contentType != "" {
				contentType += ":"
			}
			content.WriteString(contentType + digester.Digest().Encoded())
		}
		return "multi", digest.Canonical.FromString(content.String())
	}
}
