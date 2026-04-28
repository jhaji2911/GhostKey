package main

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestInferGhostEnvAssignments(t *testing.T) {
	existing := map[string]string{
		"OPENAI_API_KEY": "already-set",
	}

	got := inferGhostEnvAssignments([]string{
		"GHOST::openai-prod",
		"GHOST::anthropic",
		"GHOST::github-ci",
		"GHOST::unknown",
	}, existing)

	want := []string{
		"ANTHROPIC_API_KEY=GHOST::anthropic",
		"GITHUB_TOKEN=GHOST::github-ci",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inferGhostEnvAssignments() = %#v, want %#v", got, want)
	}
}

func TestParseWrapEnvMappings(t *testing.T) {
	got, err := parseWrapEnvMappings([]string{"OPENAI_API_KEY=GHOST::openai"})
	if err != nil {
		t.Fatalf("parseWrapEnvMappings(): %v", err)
	}

	want := []string{"OPENAI_API_KEY=GHOST::openai"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseWrapEnvMappings() = %#v, want %#v", got, want)
	}
}

func TestMergeEnvAssignmentsOverridesExisting(t *testing.T) {
	base := []string{"FOO=1", "BAR=2"}
	assignments := []string{"BAR=override", "BAZ=3"}

	got := mergeEnvAssignments(base, assignments)
	want := []string{"FOO=1", "BAR=override", "BAZ=3"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeEnvAssignments() = %#v, want %#v", got, want)
	}
}

func TestSecretsFileUpsertAndRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.yaml")

	if err := upsertSecretsFileMapping(path, "GHOST::openai", "sk-real"); err != nil {
		t.Fatalf("upsertSecretsFileMapping(): %v", err)
	}

	sf, err := loadSecretsFile(path)
	if err != nil {
		t.Fatalf("loadSecretsFile(): %v", err)
	}
	if sf.Mappings["GHOST::openai"] != "sk-real" {
		t.Fatalf("mapping not persisted: %#v", sf.Mappings)
	}

	if err := upsertSecretsFileMapping(path, "GHOST::openai", "sk-new"); err != nil {
		t.Fatalf("upsertSecretsFileMapping(update): %v", err)
	}
	sf, err = loadSecretsFile(path)
	if err != nil {
		t.Fatalf("loadSecretsFile(updated): %v", err)
	}
	if sf.Mappings["GHOST::openai"] != "sk-new" {
		t.Fatalf("mapping not updated: %#v", sf.Mappings)
	}

	removed, err := removeSecretsFileMapping(path, "GHOST::openai")
	if err != nil {
		t.Fatalf("removeSecretsFileMapping(): %v", err)
	}
	if !removed {
		t.Fatal("expected mapping to be removed")
	}

	sf, err = loadSecretsFile(path)
	if err != nil {
		t.Fatalf("loadSecretsFile(after remove): %v", err)
	}
	if _, ok := sf.Mappings["GHOST::openai"]; ok {
		t.Fatalf("mapping still present after remove: %#v", sf.Mappings)
	}
}

func TestDefaultGhostKeyDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	got, err := defaultGhostKeyDir()
	if err != nil {
		t.Fatalf("defaultGhostKeyDir(): %v", err)
	}
	want := filepath.Join(home, ".ghostkey")
	if got != want {
		t.Fatalf("defaultGhostKeyDir() = %q, want %q", got, want)
	}
}
