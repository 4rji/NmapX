package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Verifica si el usuario puede ejecutar sudo sin contraseña
func checkSudoPrivileges() bool {
	cmd := exec.Command("sudo", "-n", "true")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// Función para ejecutar comandos con privilegios elevados
func runWithPrivileges(cmd string, args ...string) error {
	// Construir el comando correctamente: sudo nmap ...
	allArgs := append([]string{cmd}, args...)
	fmt.Printf("[DEBUG] Running: sudo %s\n", strings.Join(allArgs, " "))
	fullCmd := exec.Command("sudo", allArgs...)
	fullCmd.Stdout = os.Stdout
	fullCmd.Stderr = os.Stderr
	fullCmd.Stdin = os.Stdin
	return fullCmd.Run()
}

// Realiza la fase de descubrimiento de hosts
func performHostDiscovery(state *AppState) {
	fmt.Println("[1] Host discovery")
	err := runWithPrivileges("nmap", "-sn", state.target, "-oG", state.scanDir+"/pingsweep.gnmap")
	if err != nil {
		fmt.Printf("Error during host discovery: %v\n", err)
		return
	}

	f, _ := os.Open(state.scanDir + "/pingsweep.gnmap")
	defer f.Close()
	hf, _ := os.Create(state.scanDir + "/hosts.txt")
	defer hf.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasSuffix(line, "Up") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				hf.WriteString(parts[1] + "\n")
			}
		}
	}
}

// Realiza el escaneo de puertos
func performPortScan(state *AppState) {
	fmt.Println("[2] Port scan (fast mode)")
	err := runWithPrivileges("nmap", "-sS", "-sV", "-T4", "--top-ports", "1000", "-iL",
		state.scanDir+"/hosts.txt", "-oN", state.scanDir+"/ports.nmap")
	if err != nil {
		fmt.Printf("Error during port scan: %v\n", err)
		return
	}
}

// Inicia el proceso de escaneo
func startScan(state *AppState) {
	if !checkSudoPrivileges() {
		fmt.Println("\033[1;31m[!] Necesitas privilegios sudo para ejecutar este programa. Ejecuta el programa desde una terminal y asegúrate de tener permisos sudo.\033[0m")
		return
	}
	go func() {
		// Configurar directorios de salida
		ts := time.Now().Format("20060102_150405")
		state.scanDir = "test_" + ts
		os.MkdirAll(state.scanDir, 0755)
		state.htmlPath = state.scanDir + "/report.html"

		// Obtener información de red
		hostIP, _ := run("sh", "-c", `ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -n1`)
		gateway, _ := run("sh", "-c", `netstat -rn | grep default | grep -v "link#" | awk '{print $2}' | head -n1`)
		subnet, _ := run("sh", "-c", `ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -n1 | awk -F. '{print $1"."$2"."$3".0/24"}'`)

		// Realizar escaneo
		performHostDiscovery(state)
		performPortScan(state)

		// Generar reporte
		hostsData, _ := ioutil.ReadFile(state.scanDir + "/hosts.txt")
		portsData, _ := ioutil.ReadFile(state.scanDir + "/ports.nmap")
		htmlContent := generateHTMLReport(state, hostIP, gateway, subnet, hostsData, portsData)
		ioutil.WriteFile(state.htmlPath, []byte(htmlContent), 0644)

		// Iniciar servidor web
		fs := http.FileServer(http.Dir(state.scanDir))
		http.Handle("/", fs)
		port := "8080"
		webURL := fmt.Sprintf("http://localhost:%s", port)
		fmt.Printf("\n\033[1;32m[+] Web server started at %s\033[0m\n", webURL)
		go http.ListenAndServe(":"+port, nil)

		// Mostrar popup con resultados
		showCompletionPopup(state)
	}()
}
