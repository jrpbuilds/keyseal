package repo_test

import (
	"testing"

	"github.com/jrpbuilds/keyseal/internal/repo"
)

func TestMatchLogicalGlob(t *testing.T) {
	tests := []struct {
		name     string
		logical  string
		pattern  string
		want     bool
		wantErr  bool
	}{
		{name: "exact match", logical: "production/app", pattern: "production/app", want: true},
		{name: "exact miss", logical: "production/app", pattern: "production/other", want: false},
		{name: "one segment star", logical: "production/app", pattern: "production/*", want: true},
		{name: "one segment star does not cross", logical: "production/app/extra", pattern: "production/*", want: false},
		{name: "double star deep", logical: "production/app/extra", pattern: "production/**", want: true},
		{name: "double star same segment", logical: "production", pattern: "production/**", want: true},
		{name: "double star mid", logical: "production/app/extra", pattern: "production/**/extra", want: true},
		{name: "no prefix match", logical: "production-extra", pattern: "production/**", want: false},
		{name: "no suffix prefix", logical: "other/production", pattern: "production/**", want: false},
		{name: "empty pattern rejected", logical: "production/app", pattern: "", wantErr: true},
		{name: "absolute rejected", logical: "production/app", pattern: "/production/**", wantErr: true},
		{name: "dotdot rejected", logical: "production/app", pattern: "../production", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := repo.MatchLogicalGlob(tt.logical, tt.pattern)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("MatchLogicalGlob returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("MatchLogicalGlob(%q, %q) = %v, want %v", tt.logical, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestMatchesAnyLogicalGlobExcludeWinsSemantics(t *testing.T) {
	ok, err := repo.MatchesAnyLogicalGlob("controller/website", []string{"controller/**"})
	if err != nil {
		t.Fatalf("MatchesAnyLogicalGlob returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected controller/website to match controller/**")
	}
}
