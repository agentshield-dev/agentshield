package ui

import (
	"bytes"
	"io/fs"
	"regexp"
	"testing"
)

var (
	assetRef  = regexp.MustCompile(`(?:src|href)="/(assets/[^"]+)"`)
	scriptTag = regexp.MustCompile(`<script\b[^>]*>`)
)

func TestBuiltAssetsAreEmbedded(t *testing.T) {
	assets := Assets()
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		t.Skip(`web UI is not built; run "make ui"`)
	}

	refs := assetRef.FindAllSubmatch(index, -1)
	if len(refs) == 0 {
		t.Fatal("index.html references no bundled assets")
	}
	for _, ref := range refs {
		if _, err := fs.Stat(assets, string(ref[1])); err != nil {
			t.Errorf("index.html references %s, which is not embedded: %v", ref[1], err)
		}
	}
}

// The service sends script-src 'self' and style-src 'self', so inline code would render a blank page.
func TestBuiltIndexHasNoInlineCode(t *testing.T) {
	index, err := fs.ReadFile(Assets(), "index.html")
	if err != nil {
		t.Skip(`web UI is not built; run "make ui"`)
	}

	for _, tag := range scriptTag.FindAll(index, -1) {
		if !bytes.Contains(tag, []byte(" src=")) {
			t.Errorf("index.html has an inline script: %s", tag)
		}
	}
	for _, inline := range []string{"<style", " style="} {
		if bytes.Contains(index, []byte(inline)) {
			t.Errorf("index.html contains inline styling (%q)", inline)
		}
	}
}
