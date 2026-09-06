package cli

import (
	"flag"
	"testing"
)

func TestExtractBoolFlag(t *testing.T) {
	args, found := extractBoolFlag([]string{"run_123", "--json", "--tail"}, "json")
	if !found {
		t.Fatalf("flag not found")
	}
	if len(args) != 2 || args[0] != "run_123" || args[1] != "--tail" {
		t.Fatalf("args=%v", args)
	}
}

func TestExtractBoolFlagMissing(t *testing.T) {
	args, found := extractBoolFlag([]string{"run_123"}, "json")
	if found {
		t.Fatalf("flag should not be found")
	}
	if len(args) != 1 || args[0] != "run_123" {
		t.Fatalf("args=%v", args)
	}
}

func TestFlagWasSet(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	value := fs.String("id", "", "")
	fs.Bool("json", false, "")
	if err := fs.Parse([]string{"--id", "blue-lobster"}); err != nil {
		t.Fatal(err)
	}
	if *value != "blue-lobster" {
		t.Fatalf("id=%q", *value)
	}
	if !flagWasSet(fs, "id") {
		t.Fatal("id should be marked set")
	}
	if !FlagWasSet(fs, "id") {
		t.Fatal("exported id check should be marked set")
	}
	if flagWasSet(fs, "json") {
		t.Fatal("json should not be marked set")
	}
	if FlagWasSet(fs, "json") {
		t.Fatal("exported json check should not be marked set")
	}
}
