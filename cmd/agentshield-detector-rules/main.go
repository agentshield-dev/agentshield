// Command agentshield-detector-rules is a compatibility entry point for
// `agentshield rules`. New installations should use the unified agentshield
// command; both interfaces share the same implementation.
package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/agentshield-dev/agentshield/pkg/rulescli"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	return rulescli.Run(ctx, args, output)
}
