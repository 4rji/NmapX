package main

import (
	"bytes"
	"os/exec"
	"os/user"
	"strings"
)

// Run ejecuta un comando y retorna su salida
// Automatically adds sudo when needed
func Run(cmd string, args ...string) (string, error) {
	// List of commands that require sudo privileges
	sudoCommands := map[string]bool{
		"nmap": true,
	}

	var command *exec.Cmd

	// Check if we're running as root
	isRoot := false
	if u, err := user.Current(); err == nil {
		isRoot = (u.Uid == "0")
	}

	// Add sudo if the command needs elevated privileges and we're not already root
	if sudoCommands[cmd] && !isRoot {
		sudoArgs := append([]string{cmd}, args...)
		command = exec.Command("sudo", sudoArgs...)
	} else {
		command = exec.Command(cmd, args...)
	}

	var out bytes.Buffer
	command.Stdout = &out
	command.Stderr = &out
	err := command.Run()
	return out.String(), err
}

// GetFirstLine obtiene la primera línea no vacía de una cadena
func GetFirstLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}
