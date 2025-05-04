package main

import (
	"fmt"
	"html"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// Aplica estilos HTML al reporte de puertos
func stylePortsOutput(portsData []byte) string {
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

// Genera el contenido HTML del reporte
func generateHTMLReport(state *AppState, hostIP, gateway, subnet string, hostsData, portsData []byte) string {
	escapedPorts := stylePortsOutput(portsData)

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
  <h1>Network Scan Report</h1>
  <small>Generated: %s</small>
</div>

<div class="cards">
  <div class="card"><h3>Host IP</h3><p>%s</p></div>
  <div class="card"><h3>Target</h3><p>%s</p></div>
  <div class="card"><h3>Default Gateway</h3><p>%s</p></div>
</div>

<div class="section">
  <h2>Nmap Command</h2>
  <pre>%s</pre>
</div>

<div class="section">
  <h2>Live Hosts</h2>
  <ul class="list">
`, time.Now().Format("2006-01-02 15:04:05"),
		html.EscapeString(getFirstLine(hostIP)),
		html.EscapeString(state.target),
		html.EscapeString(getFirstLine(gateway)),
		html.EscapeString("nmap "+strings.Join(state.selectedNmapArgs, " ")))

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

// Muestra un popup con los resultados del escaneo
func showCompletionPopup(state *AppState) {
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
		list.AddItem("[HTML Report] http://localhost:8080/report.html", "", 0, nil)
		for _, r := range logFiles {
			list.AddItem(r, "", 0, nil)
		}
		list.SetBorder(true).SetTitle("Generated files").SetBackgroundColor(tcell.ColorDarkBlue)

		// Open in browser on selection
		list.SetSelectedFunc(func(ix int, mainText, secText string, shortcut rune) {
			if ix == 0 {
				// Open the HTML report in the browser
				url := "http://localhost:8080/report.html"
				var cmd *exec.Cmd
				if runtime.GOOS == "darwin" {
					cmd = exec.Command("open", url)
				} else if runtime.GOOS == "linux" {
					cmd = exec.Command("xdg-open", url)
				}
				if cmd != nil {
					cmd.Start()
				}
			} else if ix-1 < len(logFiles) {
				// Opcional: copiar ruta al portapapeles
				path := logFiles[ix-1]
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

		exitBtn := tview.NewButton("Exit").SetSelectedFunc(func() {
			os.Exit(0)
		})
		exitBtn.SetBackgroundColor(tcell.ColorGreen)
		exitBtn.SetLabelColor(tcell.ColorBlack)

		list.SetDoneFunc(func() {
			state.app.SetRoot(state.flex, true)
		})

		popup := tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(tview.NewTextView().SetText("[green]Scan finished![white]\nOnly files from this scan are shown.\n[yellow]Web report: [white]http://localhost:8080/report.html\n").SetDynamicColors(true), 4, 0, false).
			AddItem(list, 0, 1, true).
			AddItem(exitBtn, 3, 0, false)

		// Manejar Tab y Shift+Tab para cambiar el foco entre la lista y el botón Exit
		popup.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
			if event.Key() == tcell.KeyTab {
				if state.app.GetFocus() == list {
					state.app.SetFocus(exitBtn)
				} else {
					state.app.SetFocus(list)
				}
				return nil
			}
			if event.Key() == tcell.KeyBacktab {
				if state.app.GetFocus() == exitBtn {
					state.app.SetFocus(list)
				} else {
					state.app.SetFocus(exitBtn)
				}
				return nil
			}
			if event.Key() == tcell.KeyEsc {
				os.Exit(0)
			}
			return event
		})

		state.app.SetRoot(popup, true)
	})
}
