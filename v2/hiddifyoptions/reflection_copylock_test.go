package hiddifyoptions

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestOptionsReflectionDoesNotCopyLocks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, "go", "vet", "-copylocks", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("options must pass the protobuf copylock check: %v\n%s", err, output)
	}
}
