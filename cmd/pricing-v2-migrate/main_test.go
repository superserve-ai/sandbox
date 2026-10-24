package main

import "testing"

func TestApplyRequiresExplicitHumanAuthority(t *testing.T) {
	getenv := func(key string) string {
		if key == "SYSTEM_TEAM_ID" {
			return "10000000-0000-4000-8000-000000000001"
		}
		if key == "TEAM_CREATION_REGION" {
			return "test-region"
		}
		return ""
	}
	for _, args := range [][]string{
		{"apply"},
		{"apply", "--actor", "operator@example.com", "--reason", "launch"},
		{"apply", "--confirm", "--reason", "launch"},
		{"apply", "--confirm", "--actor", "operator@example.com"},
		{"apply", "--confirm", "--actor", "  ", "--reason", "launch"},
		{"apply", "--confirm", "--actor", "operator@example.com", "--reason", "  "},
	} {
		if _, err := parse(args, getenv); err == nil {
			t.Errorf("accepted apply without authority: %v", args)
		}
	}
	if _, err := parse([]string{"apply", "--confirm", "--actor", "operator@example.com", "--reason", "launch"}, getenv); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRefusesInvalidSystemTeamBeforeConnecting(t *testing.T) {
	for _, value := range []string{"", "invalid", "00000000-0000-0000-0000-000000000000"} {
		getenv := func(key string) string {
			if key == "TEAM_CREATION_REGION" {
				return "usw"
			}
			if key == "SYSTEM_TEAM_ID" {
				return value
			}
			return ""
		}
		if _, err := parse([]string{"apply", "--confirm", "--actor", "operator@example.com", "--reason", "launch"}, getenv); err == nil {
			t.Errorf("accepted system team %q", value)
		}
	}
}

func TestAdoptionWritesRequireAuthorityAndCurrentEpoch(t *testing.T) {
	getenv := func(key string) string {
		switch key {
		case "SYSTEM_TEAM_ID":
			return "10000000-0000-4000-8000-000000000001"
		case "TEAM_CREATION_REGION":
			return "usw"
		}
		return ""
	}
	for _, command := range []string{"prepare", "capture", "release"} {
		if _, err := parse([]string{command}, getenv); err == nil {
			t.Fatalf("accepted unconfirmed %s", command)
		}
	}
	args := []string{"release", "--confirm", "--actor", "operator@example.com", "--reason", "release"}
	if _, err := parse(args, getenv); err == nil {
		t.Fatal("accepted release without epoch and evidence")
	}
	args = append(args, "--epoch", "10000000-0000-4000-8000-000000000002", "--evidence-file", "/tmp/example-evidence.json")
	if _, err := parse(args, getenv); err != nil {
		t.Fatal(err)
	}
}
