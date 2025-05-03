package main

import (
	"fmt"
	"os"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
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

	// Menú de selección de opciones de escaneo
	options := []struct {
		label    string
		desc     string
		selected bool
	}{
		{"Host discovery (Ping scan)", "-sn", true},
		{"ARP scan (localnet)", "arp-scan", false},
		{"Fast TCP scan (top 1000)", "-sS -sV -T4 --top-ports 1000", true},
		{"Medium scan (TCP/UDP/OS)", "-sS -O -sV -sU --top-ports 20 -T4", false},
		{"Full scan (all TCP/UDP/OS)", "-sS -sU -O -sV -T4", false},
		{"SMB enumeration", "--script smb-enum-shares,smb-os-discovery -p 445", false},
		{"SNMP info", "-sU -p 161 --script snmp-info", false},
		{"Vulnerability scan", "--script vuln", false},
	}

	form := tview.NewForm()
	for i := range options {
		idx := i
		form.AddCheckbox(options[i].label, options[i].selected, func(checked bool) {
			options[idx].selected = checked
		})
	}
	form.AddButton("Start scan", func() {
		// Construir el comando nmap según las selecciones
		var nmapArgs []string
		var extraCmds []string
		if options[0].selected { // Host discovery
			nmapArgs = append(nmapArgs, "-sn")
		}
		if options[1].selected { // ARP scan
			extraCmds = append(extraCmds, fmt.Sprintf("arp-scan --localnet -o %s/arp.txt", state.scanDir))
		}
		if options[2].selected { // Fast TCP
			nmapArgs = append(nmapArgs, "-sS", "-sV", "-T4", "--top-ports", "1000")
		}
		if options[3].selected { // Medium
			nmapArgs = append(nmapArgs, "-sS", "-O", "-sV", "-sU", "--top-ports", "20", "-T4")
		}
		if options[4].selected { // Full
			nmapArgs = append(nmapArgs, "-sS", "-sU", "-O", "-sV", "-T4")
		}
		if options[5].selected { // SMB
			nmapArgs = append(nmapArgs, "--script", "smb-enum-shares,smb-os-discovery", "-p", "445")
		}
		if options[6].selected { // SNMP
			nmapArgs = append(nmapArgs, "-sU", "-p", "161", "--script", "snmp-info")
		}
		if options[7].selected { // Vuln
			nmapArgs = append(nmapArgs, "--script", "vuln")
		}
		// Guardar las selecciones en el estado
		state.selectedNmapArgs = nmapArgs
		state.selectedExtraCmds = extraCmds

		// Iniciar monitores y escaneo
		startProcessMonitor(state)
		startPortsFileMonitor(state)
		setupOutputRedirection(state)
		startScan(state)
		state.app.SetRoot(state.flex, true)
	})
	form.SetBorder(true).SetTitle("Customize your scan (space to select)").SetTitleColor(tcell.ColorGreen)
	state.app.SetRoot(form, true)
	if err := state.app.Run(); err != nil {
		panic(err)
	}
}
