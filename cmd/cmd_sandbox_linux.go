//go:build linux && !android

package cmd

import (
	"os"

	"github.com/hiddify/hiddify-core/v2/hcore/sandbox"
	"github.com/spf13/cobra"
)

func init() {
	mainCommand.AddCommand(&cobra.Command{
		Use:                "experimental-sandbox [--proxy-file FILE] -- COMMAND [ARGS...]",
		Short:              "Experimental rootless console sandbox; stdin is its revocation lease",
		Hidden:             true,
		DisableFlagParsing: true,
		Run: func(_ *cobra.Command, args []string) {
			os.Exit(sandbox.Run(args))
		},
	})
}
