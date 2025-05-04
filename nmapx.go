package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	// Privilege check before any UI
	if !checkSudoPrivileges() {
		fmt.Println("You need sudo privileges to run this program!\nRun 'sudo -v' in your terminal to assign privileges, or 'sudo -k' to remove them.\nMake sure to run this program from a terminal where you can enter your sudo password.")
		os.Exit(1)
	}

	// Verificar argumentos
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./test_scan_report <CIDR>")
		os.Exit(1)
	}

	// Configurar la aplicación
	state := setupUI()
	state.target = os.Args[1]

	// Mostrar la interfaz TUI para personalizar el comando nmap
	nmapCmd := ShowNmapTUI(state)
	if nmapCmd == "" {
		fmt.Println("No scan selected. Exiting.")
		os.Exit(0)
	}

	// Actualizar el título de la barra superior con el comando Nmap
	if state.title != nil {
		state.title.SetText("[green]4rji - nmapX    [white]|    [yellow]Command: [white]" + nmapCmd)
	}

	// Parsear el comando nmap
	parts := strings.Fields(nmapCmd)
	if len(parts) < 2 {
		fmt.Println("Invalid nmap command")
		os.Exit(1)
	}

	// Guardar las selecciones en el estado
	state.selectedNmapArgs = parts[1:] // Skip the "nmap" command itself
	state.selectedExtraCmds = []string{}

	// Iniciar monitores y escaneo
	startProcessMonitor(state)
	startPortsFileMonitor(state)
	setupOutputRedirection(state)
	startScan(state)
	state.app.SetRoot(state.flex, true)

	if err := state.app.Run(); err != nil {
		panic(err)
	}
}
