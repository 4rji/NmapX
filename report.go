package main

import (
	"fmt"
	"html"
	"io/ioutil"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// StylePortsOutput aplica estilos HTML al reporte de puertos
func StylePortsOutput(portsData []byte) string {
	escapedPorts := html.EscapeString(string(portsData))

	// Destacar protocolos (22/tcp, 53/udp, etc)
	reProto := regexp.MustCompile(`(\d+)/(tcp|udp)`)
	escapedPorts = reProto.ReplaceAllString(escapedPorts, `<span class="proto">$0</span>`)

	// Destacar servicios comunes
	reSvc := regexp.MustCompile(`\b(ssh|http|domain|nginx|dnsmasq)\b`)
	escapedPorts = reSvc.ReplaceAllString(escapedPorts, `<span class="svc">$1</span>`)

	// Destacar estados de puertos
	reOpen := regexp.MustCompile(`\bopen\b`)
	reClosed := regexp.MustCompile(`\bclosed\b`)
	reFiltered := regexp.MustCompile(`\bfiltered\b`)
	escapedPorts = reOpen.ReplaceAllString(escapedPorts, `<span class="open">open</span>`)
	escapedPorts = reClosed.ReplaceAllString(escapedPorts, `<span class="closed">closed</span>`)
	escapedPorts = reFiltered.ReplaceAllString(escapedPorts, `<span class="filtered">filtered</span>`)

	return escapedPorts
}

// GenerateHTMLReport genera el contenido HTML del reporte
func GenerateHTMLReport(state *AppState, hostIP, gateway, subnet string, hostsData, portsData []byte) string {
	escapedPorts := StylePortsOutput(portsData)

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Scan Report</title>
<style>
:root{--primary:#0d6efd;--bg:#f5f7fa;--card:#fff;--border:#dee2e6;}
*{box-sizing:border-box;margin:0;padding:0;font-family:"Segoe UI",Arial,sans-serif;}
body{background:var(--bg);padding:1rem 2rem;color:#212529;}
.banner{background:linear-gradient(90deg,#0045ff 0%%,#009dff 100%%);color:#fff;border-radius:8px;padding:1.5rem;margin-bottom:1.5rem;}
.banner h1{font-size:1.75rem;margin-bottom:.3rem;}
.cards{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem;}
.card{flex:1 1 200px;background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem;}
.section{margin-bottom:2rem;}
.section h2{font-size:1.1rem;margin-bottom:.6rem;color:#0045ff;}
.list{list-style:none;padding-left:0;}
.list li{padding:.25rem .5rem;border-bottom:1px solid var(--border);}
pre{
  background:#1e1e1e;
  color:#e8e8e8;
  padding:1rem;
  border-radius:8px;
  overflow-x:auto;
  font-size:.95rem;
  line-height:1.4;
  font-family:"Consolas","Courier New",monospace;
}
.open { color: #28a745; font-weight: bold; }
.closed { color: #dc3545; font-weight: bold; }
.filtered { color: #ffc107; font-weight: bold; }
.proto { color: #0dcaf0; font-weight: bold; }
.svc { color: #6610f2; font-weight: bold; }
</style>
</head><body>

<div class="banner">
  <h1>Network Scan Report (Test Mode)</h1>
  <small>Generated: %s</small>
</div>

<div class="cards">
  <div class="card"><h3>Host IP</h3><p>%s</p></div>
  <div class="card"><h3>Network</h3><p>%s</p></div>
  <div class="card"><h3>Default Gateway</h3><p>%s</p></div>
</div>

<div class="section">
  <h2>Live Hosts</h2>
  <ul class="list">
`, time.Now().Format("2006-01-02 15:04:05"),
		html.EscapeString(GetFirstLine(hostIP)),
		html.EscapeString(subnet),
		html.EscapeString(GetFirstLine(gateway)))

	for _, line := range strings.Split(string(hostsData), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			htmlContent += fmt.Sprintf("    <li>%s</li>\n", html.EscapeString(line))
		}
	}

	htmlContent += fmt.Sprintf(`  </ul>
</div>

<div class="section">
  <h2>Port Scan Results</h2>
  <pre>%s</pre>
</div>

</body></html>`, escapedPorts)

	return htmlContent
}

// ShowCompletionPopup muestra un popup con los resultados del escaneo
func ShowCompletionPopup(state *AppState) {
	state.app.QueueUpdateDraw(func() {
		// Archivos relevantes del escaneo actual
		var logFiles []string
		files, _ := ioutil.ReadDir(state.scanDir)
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".nmap") ||
				strings.HasSuffix(f.Name(), ".gnmap") ||
				f.Name() == "hosts.txt" {
				logFiles = append(logFiles, state.scanDir+"/"+f.Name())
			}
		}

		list := tview.NewList().ShowSecondaryText(false)
		list.AddItem("[Reporte HTML] "+state.htmlPath, "", 0, nil)
		for _, r := range logFiles {
			list.AddItem(r, "", 0, nil)
		}
		list.SetBorder(true).SetTitle("Archivos generados").SetBackgroundColor(tcell.ColorDarkBlue)

		// Copiar al portapapeles al seleccionar
		list.SetSelectedFunc(func(ix int, mainText, secText string, shortcut rune) {
			var path string
			if ix == 0 {
				// Primer item es el HTML
				path = state.htmlPath
			} else if ix-1 < len(logFiles) {
				path = logFiles[ix-1]
			}
			if path != "" {
				// Copiar al portapapeles según SO
				if runtime.GOOS == "darwin" {
					cmd := exec.Command("pbcopy")
					in, _ := cmd.StdinPipe()
					cmd.Start()
					in.Write([]byte(path))
					in.Close()
					cmd.Wait()
				} else if runtime.GOOS == "linux" {
					cmd := exec.Command("xclip", "-selection", "clipboard")
					in, _ := cmd.StdinPipe()
					cmd.Start()
					in.Write([]byte(path))
					in.Close()
					cmd.Wait()
				}
			}
		})

		okBtn := tview.NewButton("OK").SetSelectedFunc(func() {
			state.app.SetRoot(state.flex, true)
		})
		okBtn.SetBackgroundColor(tcell.ColorGreen)
		okBtn.SetLabelColor(tcell.ColorBlack)

		list.SetDoneFunc(func() {
			state.app.SetRoot(state.flex, true)
		})

		popup := tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(tview.NewTextView().SetText("[green]Reporte finalizado![white]\nSolo se muestran los archivos de este escaneo.\n[yellow]Servidor web: [white]http://localhost:8080\n").SetDynamicColors(true), 4, 0, false).
			AddItem(list, 0, 1, true).
			AddItem(okBtn, 3, 0, false)

		popup.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
			if event.Key() == tcell.KeyEsc {
				state.app.SetRoot(state.flex, true)
				return nil
			}
			return event
		})

		state.app.SetRoot(popup, true)
	})
}
