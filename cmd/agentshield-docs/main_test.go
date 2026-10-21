package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fixtureFile(t *testing.T, root, name, content string) {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestDocGoConversion(t *testing.T) {
	root := t.TempDir()
	fixtureFile(t, root, "pkg/example/doc.go", `// Package example provides an [Event].
//
// # Invariants
//
//   - Keep every observation.
//
// Example:
//
//     example.Run()
package example
`)
	fixtureFile(t, root, "pkg/example/implementation.go", "not Go syntax; this file must never be parsed")
	fixtureFile(t, root, "node_modules/ignored/doc.go", "not Go syntax")
	fixtureFile(t, root, ".cache/ignored/doc.go", "not Go syntax")
	pages, err := generatePages(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 3 {
		t.Fatalf("got %d pages; want package page and two indexes", len(pages))
	}
	for _, want := range []string{"Package example", "## Invariants", "Keep every observation.", "example.Run()", "https://pkg.go.dev/" + modulePath + "/pkg/example#Event"} {
		if !strings.Contains(pages[0].Content, want) {
			t.Errorf("package Markdown omits %q", want)
		}
	}
	second, err := generatePages(root)
	if err != nil || !reflect.DeepEqual(pages, second) {
		t.Fatalf("generation is not deterministic: %v", err)
	}
	output := t.TempDir()
	if err := run([]string{"--source-root", root, "--output-dir", output}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(output, "go", "pkg-example.md"))
	if err != nil || string(content) != pages[0].Content {
		t.Fatalf("command output differs from generated Markdown: %v", err)
	}
}

func TestEveryDocGoProducesMarkdown(t *testing.T) {
	pages, err := generatePages("../..")
	if err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	if err := writeReferences(output, pages); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, directory := range []string{"pkg", "plugins"} {
		err := fs.WalkDir(os.DirFS("../../"+directory), ".", func(name string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || entry.Name() != "doc.go" {
				return nil
			}
			count++
			packagePath := path.Join(directory, path.Dir(name))
			filename := filepath.Join(output, "go", strings.ReplaceAll(packagePath, "/", "-")+".md")
			if _, err := os.Stat(filename); err != nil {
				t.Errorf("%s/doc.go did not produce Markdown: %v", packagePath, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if count == 0 || len(pages) != count+2 {
		t.Fatalf("got %d pages for %d doc.go files; want one per file and two indexes", len(pages), count)
	}
	content, err := os.ReadFile(filepath.Join(output, "go", "pkg-telemetry.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Pipeline position", "Invariants", "OTLP/HTTP or provider-native receiver", "Every event has a stable event ID"} {
		if !strings.Contains(string(content), want) {
			t.Errorf("telemetry Markdown omits %q", want)
		}
	}
	if strings.Contains(string(content), "func NewPipeline") {
		t.Fatal("exported declarations were copied into package commentary")
	}
}

func TestInvalidInputs(t *testing.T) {
	for _, args := range [][]string{{"unexpected"}, {"--unknown"}, {"--output-dir"}, {"--output-dir="}} {
		if err := run(args); err == nil {
			t.Errorf("accepted invalid arguments %v", args)
		}
	}
	root := t.TempDir()
	if _, err := generatePages(root); err == nil {
		t.Fatal("accepted an empty source tree")
	}
	fixtureFile(t, root, "doc.go", "package example\n")
	if _, err := generatePages(root); err == nil {
		t.Fatal("accepted doc.go without package commentary")
	}
	fixtureFile(t, root, "doc.go", "invalid Go")
	if _, err := generatePages(root); err == nil {
		t.Fatal("accepted invalid doc.go")
	}
}

func TestManagedOutput(t *testing.T) {
	root := t.TempDir()
	fixtureFile(t, root, "authored.md", "Keep this authored page.\n")
	if err := writeReferences(root, []referencePage{newPage("old.md", "Old", "old")}); err != nil {
		t.Fatal(err)
	}
	if err := writeReferences(root, []referencePage{newPage("go/current.md", "Current", "current")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "old.md")); !os.IsNotExist(err) {
		t.Fatal("stale generated page was not removed")
	}
	if content, err := os.ReadFile(filepath.Join(root, "authored.md")); err != nil || string(content) != "Keep this authored page.\n" {
		t.Fatal("authored page changed")
	}
	if err := writeReferences(root, []referencePage{newPage("authored.md", "No", "no")}); err == nil {
		t.Fatal("overwrote an authored page")
	}
	manifest, err := os.ReadFile(filepath.Join(root, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	if err := json.Unmarshal(manifest, &names); err != nil || !reflect.DeepEqual(names, []string{"go/current.md"}) {
		t.Fatalf("invalid generated manifest: %s (%v)", manifest, err)
	}
}

func TestManagedOutputRejectsEscapes(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	fixtureFile(t, outside, "outside.md", generatedMarker+"\nKeep this.\n")
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, name := range []string{"../outside.md", "escape/outside.md", "/absolute.md"} {
		if err := writeReferences(root, []referencePage{newPage(name, "No", "no")}); err == nil {
			t.Errorf("accepted unsafe output path %s", name)
		}
	}
	fixtureFile(t, root, manifestName, `["../outside.md"]`)
	if err := writeReferences(root, nil); err == nil {
		t.Fatal("accepted traversal in previous manifest")
	}
	content, err := os.ReadFile(filepath.Join(outside, "outside.md"))
	if err != nil || string(content) != generatedMarker+"\nKeep this.\n" {
		t.Fatal("file outside output root changed")
	}
}
