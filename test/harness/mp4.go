// Package harness provides artifact-level verifiers for the Plate test suite.
//
// The house rule (spec §7): verify the ARTIFACT, not the flag. Every helper here
// inspects the real bytes a real engine produced — the actual MP4 box layout,
// the actual decoded pixels of a real rendition — never that an option was
// passed or a function was called. A test that asserts `-movflags +faststart`
// was on the command line passes even when the output is broken; a test that
// walks the output file's atoms and finds `moov` before `mdat` cannot.
package harness

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Atom is one top-level box in an MP4/ISO-BMFF file: its four-character type and
// the byte offset at which it begins in the file.
type Atom struct {
	Type   string
	Offset int64
	Size   int64
}

// TopLevelAtoms walks the top-level box structure of an MP4 file and returns the
// atoms in the order they physically appear in the file. It reads only the box
// headers, seeking over each box's payload, so it is cheap even on a large
// master. This is the ground truth for faststart: a progressive-streaming MP4
// has its `moov` atom before its `mdat` atom in the file, and this reports that
// physical order directly from the bytes.
//
// It parses 32-bit and 64-bit (size==1) box sizes and stops at a size==0 box
// ("extends to EOF"), which is the standard ISO-BMFF framing.
func TopLevelAtoms(path string) ([]Atom, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	fileSize := fi.Size()

	var atoms []Atom
	var off int64
	hdr := make([]byte, 16)

	for off < fileSize {
		// Need at least an 8-byte header (4 size + 4 type).
		if _, err := f.ReadAt(hdr[:8], off); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		size := int64(binary.BigEndian.Uint32(hdr[0:4]))
		typ := string(hdr[4:8])

		switch {
		case size == 1:
			// 64-bit largesize follows the type.
			if _, err := f.ReadAt(hdr[8:16], off+8); err != nil {
				return nil, err
			}
			size = int64(binary.BigEndian.Uint64(hdr[8:16]))
		case size == 0:
			// Box runs to end of file. Record and stop.
			atoms = append(atoms, Atom{Type: typ, Offset: off, Size: fileSize - off})
			return atoms, nil
		}

		if size < 8 {
			return nil, fmt.Errorf("harness: malformed box %q at offset %d (size %d < 8)", typ, off, size)
		}
		atoms = append(atoms, Atom{Type: typ, Offset: off, Size: size})
		off += size
	}
	return atoms, nil
}

// AtomOffset returns the byte offset of the first top-level atom of the given
// four-character type, or -1 if the atom is not present at the top level.
func AtomOffset(atoms []Atom, typ string) int64 {
	for _, a := range atoms {
		if a.Type == typ {
			return a.Offset
		}
	}
	return -1
}

// IsFaststart reports whether an MP4's top-level `moov` atom physically precedes
// its `mdat` atom — the condition a browser needs to begin painting a video
// before the whole file has downloaded (spec §5.5). Both atoms must be present
// at the top level; a fragmented MP4 with no single `mdat`, or a file missing
// either box, returns an error rather than a misleading false.
func IsFaststart(path string) (bool, error) {
	atoms, err := TopLevelAtoms(path)
	if err != nil {
		return false, err
	}
	moov := AtomOffset(atoms, "moov")
	mdat := AtomOffset(atoms, "mdat")
	if moov < 0 {
		return false, fmt.Errorf("harness: no top-level moov atom in %s (atoms: %v)", path, atomTypes(atoms))
	}
	if mdat < 0 {
		return false, fmt.Errorf("harness: no top-level mdat atom in %s (atoms: %v)", path, atomTypes(atoms))
	}
	return moov < mdat, nil
}

func atomTypes(atoms []Atom) []string {
	out := make([]string, len(atoms))
	for i, a := range atoms {
		out[i] = a.Type
	}
	return out
}
