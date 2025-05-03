package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

// GetNmapProcessCmd devuelve el comando adecuado para monitorear procesos nmap según el SO
func GetNmapProcessCmd() (string, []string) {
	// Usar ps aux para ambos sistemas
	return "bash", []string{"-c", "ps aux | grep [n]map"}
}

// StartProcessMonitor inicia el monitoreo de procesos nmap
func StartProcessMonitor(state *AppState) {
	go func() {
		for {
			cmd, args := GetNmapProcessCmd()
			out, _ := Run(cmd, args...)
			state.app.QueueUpdateDraw(func() {
				state.procPane.SetText(out)
			})
			time.Sleep(time.Second)
		}
	}()
}

// StartPortsFileMonitor inicia el monitoreo del archivo ports.nmap
func StartPortsFileMonitor(state *AppState) {
	go func() {
		var lastContent string
		for {
			// Buscar el archivo ports.nmap más reciente en el directorio test_*
			files, _ := ioutil.ReadDir(".")
			var newest string
			var newestTime time.Time
			for _, f := range files {
				if f.IsDir() && strings.HasPrefix(f.Name(), "test_") {
					p := f.Name() + "/ports.nmap"
					info, err := os.Stat(p)
					if err == nil && info.ModTime().After(newestTime) {
						newest = p
						newestTime = info.ModTime()
					}
				}
			}

			if newest != "" {
				data, err := ioutil.ReadFile(newest)
				if err == nil {
					lines := strings.Split(string(data), "\n")
					if len(lines) > 20 {
						lines = lines[len(lines)-20:]
					}
					content := strings.Join(lines, "\n")
					if content != lastContent {
						lastContent = content
						state.app.QueueUpdateDraw(func() {
							state.tailPane.SetText(content)
						})
					}
				}
			} else {
				state.app.QueueUpdateDraw(func() {
					state.tailPane.SetText("")
				})
			}
			time.Sleep(2 * time.Second)
		}
	}()
}

// SetupOutputRedirection configura la redirección de stdout y stderr al panel de logs
func SetupOutputRedirection(state *AppState) {
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w
	go func() {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			state.app.QueueUpdateDraw(func() {
				fmt.Fprintln(state.logPane, scanner.Text())
			})
		}
	}()
}
