package main

import "os"

func main() {
	if err := runMain(os.Args); err != nil {
		os.Exit(1)
	}
}

func runMain(args []string) error {
	saveOsArgs := os.Args
	os.Args = args

	cmdName := ""
	if len(args) > 1 {
		cmdName = args[1]
	}
	scmd := NewCommand(cmdName)

	err := scmd.Execute()
	os.Args = saveOsArgs
	return err
}
