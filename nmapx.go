package main

import (
	"fmt"
	"os"
)

func main() {
	// Verificar argumentos
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./test_scan_report <CIDR>")
		os.Exit(1)
	}

	// Configurar la aplicación
	state := setupUI()
	state.target = os.Args[1]
	
	// Iniciar monitores
	startProcessMonitor(state)
	startPortsFileMonitor(state)
	setupOutputRedirection(state)
	
	// Iniciar escaneo
	startScan(state)

	// Iniciar la UI
	if err := state.app.SetRoot(state.flex, true).Run(); err != nil {
		panic(err)
	}
}
