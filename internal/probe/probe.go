// Package probe is Plate's ingest verification (spec §5.3): it reads the TRUE
// properties of a stored object — dimensions, duration, codec, container — so the
// vault object records what the file actually is, and delivery ceilings are
// checked against measured reality, never against a number the caller asserted.
//
// Fail closed (spec §5.3): the vault object is created regardless (refusal is
// about DELIVERY, not STORAGE), but an unprobeable or ceiling-breaching file does
// not get promoted to a delivery rendition.
//
// Engine split (decision D4):
//   - A/V  → ffprobe (the only credible option; PeerTube's reference path).
//   - image → Go's stdlib image.DecodeConfig. Dimensions are all finalize needs
//     for the megapixel and decoded-memory math, and no-cgo keeps the container
//     and self-host story honest. TWO LIMITS are documented at the DecodeConfig
//     call site below — read them there before assuming this is complete.
package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"image"
	"io"
	"os"
	"os/exec"
	"strconv"
	"time"

	// Register the stdlib decoders so image.DecodeConfig recognises these formats.
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"

	plate "github.com/chuckyatsuk/plate/internal/plate"
)

// Result is the probed truth about an object, mapped onto the fields the
// VaultObject records (spec §3.1).
type Result struct {
	Kind      plate.MediaKind
	Width     int
	Height    int
	DurationS float64
	Codec     string
	Container string
}

// Prober reads object properties. Split so the image path needs no external
// binary and the A/V path shells to ffprobe.
type Prober struct {
	ffprobePath string
}

// New builds a Prober. ffprobePath may be empty to use "ffprobe" from PATH
// (spec §Q4 / PLATE_FFPROBE_PATH).
func New(ffprobePath string) *Prober {
	if ffprobePath == "" {
		ffprobePath = "ffprobe"
	}
	return &Prober{ffprobePath: ffprobePath}
}

// ProbeImage reads an image's dimensions from a local file using the stdlib.
//
// ⚠️ LIMIT 1 — EXIF orientation. image.DecodeConfig does NOT read EXIF
// orientation. A JPEG shot in portrait but stored landscape-with-a-rotate-flag
// reports its STORED (transposed) width/height, not its displayed orientation.
// For the megapixel and decoded-memory math this is harmless (w*h is the same
// either way), but if a future feature needs DISPLAY dimensions, this is the
// line to revisit — swap to libvips, which honours orientation (decision D4).
//
// ⚠️ LIMIT 2 — full decode cost. DecodeConfig reads only the header for most
// formats, but some decoders buffer more; at Uri's 96MP this is still cheap
// (header-only), yet it is the reason libvips (streaming, header-only guaranteed)
// is the eventual upgrade if probe cost ever shows up. Documented so the boundary
// is visible, not discovered.
func (p *Prober) ProbeImage(path string) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("probe: open image: %w", err)
	}
	defer f.Close()
	return p.ProbeImageReader(f)
}

// ProbeImageReader reads image dimensions from an io.Reader — used by the API's
// finalize with a RANGED GET of just the header bytes (review ruling 1), so a
// 300MB TIFF is never fully downloaded into the request. image.DecodeConfig reads
// only as far as the header for the formats we register, so a ~64KB prefix is
// enough for the overwhelmingly common case; a format that needs more of the file
// than the prefix provides fails closed (unprobeable), which is correct.
//
// ⚠️ LIMIT 1 — EXIF orientation: DecodeConfig does not read it; a rotated JPEG
// reports STORED (transposed) dimensions. Harmless for the megapixel/decoded-
// memory math (w*h is identical); revisit with libvips if DISPLAY dims are ever
// needed. ⚠️ LIMIT 2 — a header-only prefix: enough for JPEG/PNG/GIF headers;
// exotic formats that back-load their dimensions would need a larger prefix.
func (p *Prober) ProbeImageReader(r io.Reader) (Result, error) {
	cfg, format, err := image.DecodeConfig(r)
	if err != nil {
		// Fail closed: an image we cannot read does not get promoted (spec §5.3).
		return Result{}, fmt.Errorf("probe: decode image config: %w", err)
	}
	return Result{
		Kind:      plate.Image,
		Width:     cfg.Width,
		Height:    cfg.Height,
		Container: format, // "jpeg", "png", "gif"
	}, nil
}

// ProbeAV reads audio/video properties via ffprobe. It returns the measured
// duration/dimensions/codec/container the ceiling checks consume (spec §5.3, §5.4).
func (p *Prober) ProbeAV(ctx context.Context, path string) (Result, error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, p.ffprobePath,
		"-hide_banner", "-v", "error",
		"-show_entries", "format=duration,format_name",
		"-show_entries", "stream=codec_name,width,height,codec_type",
		"-of", "json", path,
	)
	out, err := cmd.Output()
	if err != nil {
		return Result{}, fmt.Errorf("probe: ffprobe %s: %w", path, err)
	}

	var parsed struct {
		Format struct {
			Duration   string `json:"duration"`
			FormatName string `json:"format_name"`
		} `json:"format"`
		Streams []struct {
			CodecName string `json:"codec_name"`
			CodecType string `json:"codec_type"`
			Width     int    `json:"width"`
			Height    int    `json:"height"`
		} `json:"streams"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return Result{}, fmt.Errorf("probe: parse ffprobe json: %w", err)
	}

	res := Result{Container: parsed.Format.FormatName}
	if parsed.Format.Duration != "" {
		if d, err := strconv.ParseFloat(parsed.Format.Duration, 64); err == nil {
			res.DurationS = d
		}
	}
	hasVideo := false
	for _, s := range parsed.Streams {
		if s.CodecType == "video" {
			res.Width, res.Height, res.Codec = s.Width, s.Height, s.CodecName
			hasVideo = true
			break
		}
	}
	// Kind: a file with a video stream is video; audio-only is audio. (A single
	// image frame in a video container is rare here and treated as video.)
	if hasVideo {
		res.Kind = plate.Video
	} else {
		res.Kind = plate.Audio
		// Audio-only: take the first audio stream's codec.
		for _, s := range parsed.Streams {
			if s.CodecType == "audio" {
				res.Codec = s.CodecName
				break
			}
		}
	}
	return res, nil
}
