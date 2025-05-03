package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

// Inicia el monitoreo de procesos nmap
func startProcessMonitor(state *AppState) {
	go func() {
		for {
			out, _ := run("bash", "-c", "top -b -n 1 | grep nmap")
			state.app.QueueUpdateDraw(func() { 
				state.procPane.SetText(out) 
			})
			time.Sleep(time.Second)
		}
	}()
}

// Inicia el monitoreo del archivo ports.nmap
func startPortsFileMonitor(state *AppState) {
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

// Configura la redirección de stdout y stderr al panel de logs
func setupOutputRedirection(state *AppState) {
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