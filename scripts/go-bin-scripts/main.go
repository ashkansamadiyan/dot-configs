package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./program <opacity>")
		os.Exit(1)
	}

	opacity := os.Args[1]
	command := fmt.Sprintf("alacritty msg config window.opacity=%s", opacity)
	cmd := exec.Command("sh", "-c", command)
	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to execute command:", err)
	}
}
