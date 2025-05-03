package main

import (
	"bufio"
	"bytes"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func run(cmd string, args ...string) (string, error) {
	c := exec.Command(cmd, args...)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	err := c.Run()
	return out.String(), err
}

func buildListHTML(data []byte) string {
	var b strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			b.WriteString(fmt.Sprintf("<li>%s</li>", html.EscapeString(t)))
		}
	}
	return b.String()
}

// Stream command output to a tview.TextView in real time
func streamCmdToTextView(tv *tview.TextView, cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	stdout, err := c.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := c.StderrPipe()
	if err != nil {
		return err
	}
	if err := c.Start(); err != nil {
		return err
	}
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			tv.Write([]byte(line + "\n"))
		}
	}()
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			tv.Write([]byte(line + "\n"))
		}
	}()
	return c.Wait()
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("[!] Run as root.")
	}
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./network_scan_report <CIDR>")
		os.Exit(1)
	}

	target := os.Args[1]
	ts := time.Now().Format("20060102_150405")
	outDir := "recon_" + ts
	os.MkdirAll(outDir, 0755)
	htmlPath := outDir + "/report.html"

	app := tview.NewApplication()

	// Global color scheme
	tview.Styles.PrimitiveBackgroundColor = tcell.ColorDarkBlue
	tview.Styles.ContrastBackgroundColor = tcell.ColorDarkBlue
	tview.Styles.MoreContrastBackgroundColor = tcell.ColorDarkBlue
	tview.Styles.BorderColor = tcell.ColorGreen
	tview.Styles.TitleColor = tcell.ColorGreen
	tview.Styles.GraphicsColor = tcell.ColorLightCyan
	tview.Styles.PrimaryTextColor = tcell.ColorWhite
	tview.Styles.SecondaryTextColor = tcell.ColorLightGrey

	procPane := tview.NewTextView()
	procPane.SetTitle("nmap processes")
	procPane.SetBorder(true)
	procPane.SetBackgroundColor(tcell.ColorDarkBlue)

	tailPane := tview.NewTextView()
	tailPane.SetTitle("ports.nmap (tail)")
	tailPane.SetBorder(true)
	tailPane.SetBackgroundColor(tcell.ColorDarkBlue)

	logPane := tview.NewTextView()
	logPane.SetTitle("scan log")
	logPane.SetBorder(true)
	logPane.SetBackgroundColor(tcell.ColorDarkBlue)
	logPane.SetChangedFunc(func() {
		logPane.ScrollToEnd()
		app.Draw()
	})

	leftFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(procPane, 0, 1, false).
		AddItem(tailPane, 0, 1, false)
	leftFlex.SetBackgroundColor(tcell.ColorDarkBlue)

	flex := tview.NewFlex().
		AddItem(leftFlex, 0, 1, false).
		AddItem(logPane, 0, 2, true)
	flex.SetBackgroundColor(tcell.ColorDarkBlue)

	// Monitor de procesos nmap
	go func() {
		for {
			out, _ := run("bash", "-c", "ps aux | grep [n]map")
			app.QueueUpdateDraw(func() { procPane.SetText(out) })
			time.Sleep(time.Second)
		}
	}()

	// Monitor tail del archivo ports.nmap
	go func() {
		var lastContent string
		for {
			// Buscar el archivo ports.nmap más reciente en el directorio recon_*
			files, _ := ioutil.ReadDir(".")
			var newest string
			var newestTime time.Time
			for _, f := range files {
				if f.IsDir() && strings.HasPrefix(f.Name(), "recon_") {
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
						app.QueueUpdateDraw(func() { tailPane.SetText(content) })
					}
				}
			} else {
				app.QueueUpdateDraw(func() { tailPane.SetText("") })
			}
			time.Sleep(2 * time.Second)
		}
	}()

	// Menú de selección de modo de escaneo
	scanModes := []string{
		"Fast   – TCP top 1000",
		"Medium – TCP/UDP top 20 + OS",
		"Full   – TCP all + UDP + OS",
	}
	scanList := tview.NewList().
		ShowSecondaryText(false)
	scanList.SetTitle("Select scan mode").SetBorder(true).SetBackgroundColor(tcell.ColorDarkBlue)
	for i, mode := range scanModes {
		idx := i + 1
		scanList.AddItem(fmt.Sprintf("%d) %s", idx, mode), "", rune('1'+i), nil)
	}
	scanList.SetDoneFunc(func() {
		app.SetRoot(flex, true)
	})

	scanList.SetSelectedFunc(func(ix int, mainText, secText string, shortcut rune) {
		app.SetRoot(flex, true)
		go func() {
			logLn := func(s string) { fmt.Fprintf(logPane, "%s\n", s) }

			logLn("[1] Host discovery")
			streamCmdToTextView(logPane, "nmap", "-sn", target, "-oG", outDir+"/pingsweep.gnmap")

			pf, _ := os.Open(outDir + "/pingsweep.gnmap")
			scanner := bufio.NewScanner(pf)
			hf, _ := os.Create(outDir + "/hosts.txt")
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasSuffix(line, "Up") {
					if f := strings.Fields(line); len(f) >= 2 {
						hf.WriteString(f[1] + "\n")
					}
				}
			}
			hf.Close()
			pf.Close()

			switch ix {
			case 0: // Fast
				logLn("[2] Port scan (fast)")
				streamCmdToTextView(logPane, "nmap", "-sS", "-sV", "-T4", "--top-ports", "1000", "-iL", outDir+"/hosts.txt", "-oN", outDir+"/ports.nmap")
			case 1: // Medium
				logLn("[2] Port scan (medium)")
				streamCmdToTextView(logPane, "nmap", "-sS", "-sU", "-T4", "--top-ports", "20", "-O", "-iL", outDir+"/hosts.txt", "-oN", outDir+"/ports.nmap")
			case 2: // Full
				logLn("[2] Port scan (full)")
				streamCmdToTextView(logPane, "nmap", "-sS", "-sU", "-T4", "-p-", "-O", "-iL", outDir+"/hosts.txt", "-oN", outDir+"/ports.nmap")
			}

			logLn("[3] SMB enumeration")
			streamCmdToTextView(logPane, "nmap", "--script", "smb-enum-shares,smb-os-discovery", "-p", "445", "-iL", outDir+"/hosts.txt", "-oN", outDir+"/smb.nmap")

			logLn("[4] SNMP info")
			streamCmdToTextView(logPane, "nmap", "-sU", "-p", "161", "--script", "snmp-info", "-iL", outDir+"/hosts.txt", "-oN", outDir+"/snmp.nmap")

			logLn("[5] Vuln scan")
			streamCmdToTextView(logPane, "nmap", "--script", "vuln", "-iL", outDir+"/hosts.txt", "-oN", outDir+"/vuln.nmap")

			logLn("[+] Generating HTML…")

			hosts, _ := ioutil.ReadFile(outDir + "/hosts.txt")
			ports, _ := ioutil.ReadFile(outDir + "/ports.nmap")
			smb, _ := ioutil.ReadFile(outDir + "/smb.nmap")
			snmp, _ := ioutil.ReadFile(outDir + "/snmp.nmap")
			vuln, _ := ioutil.ReadFile(outDir + "/vuln.nmap")

			escPorts := html.EscapeString(string(ports))
			// Primero protocolos (22/tcp, 53/udp, etc)
			reProto := regexp.MustCompile(`(\d+)/(tcp|udp)`)
			escPorts = reProto.ReplaceAllString(escPorts, `<span class="proto">$0</span>`)
			// Luego servicios comunes
			reSvc := regexp.MustCompile(`\b(ssh|http|domain|nginx|dnsmasq)\b`)
			escPorts = reSvc.ReplaceAllString(escPorts, `<span class="svc">$1</span>`)
			// Por último los estados
			reOpen := regexp.MustCompile(`\bopen\b`)
			reClosed := regexp.MustCompile(`\bclosed\b`)
			reFiltered := regexp.MustCompile(`\bfiltered\b`)
			escPorts = reOpen.ReplaceAllString(escPorts, `<span class="open">open</span>`)
			escPorts = reClosed.ReplaceAllString(escPorts, `<span class="closed">closed</span>`)
			escPorts = reFiltered.ReplaceAllString(escPorts, `<span class="filtered">filtered</span>`)

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
  <div class="card"><h3>Target</h3><p>%s</p></div>
  <div class="card"><h3>Hosts</h3><p>%d</p></div>
</div>

<div class="section">
  <h2>Live Hosts</h2>
  <ul class="list">
%s
  </ul>
</div>

<div class="section">
  <h2>Port Scan</h2>
  <pre>%s</pre>
</div>

<div class="section">
  <h2>SMB</h2>
  <pre>%s</pre>
</div>

<div class="section">
  <h2>SNMP</h2>
  <pre>%s</pre>
</div>

<div class="section">
  <h2>Vuln</h2>
  <pre>%s</pre>
</div>

</body></html>`,
				time.Now().Format("2006-01-02 15:04:05"),
				html.EscapeString(target),
				strings.Count(string(hosts), "\n"),
				buildListHTML(hosts), escPorts,
				html.EscapeString(string(smb)),
				html.EscapeString(string(snmp)),
				html.EscapeString(string(vuln)))

			ioutil.WriteFile(htmlPath, []byte(htmlContent), 0644)
			// Mostrar popup solo con el reporte generado y los logs del escaneo actual
			app.QueueUpdateDraw(func() {
				// Archivos relevantes del escaneo actual
				var logFiles []string
				files, _ := ioutil.ReadDir(outDir)
				for _, f := range files {
					if strings.HasSuffix(f.Name(), ".nmap") || strings.HasSuffix(f.Name(), ".gnmap") || f.Name() == "hosts.txt" {
						logFiles = append(logFiles, outDir+"/"+f.Name())
					}
				}
				list := tview.NewList().ShowSecondaryText(false)
				list.AddItem("[Reporte HTML] "+htmlPath, "", 0, nil)
				for _, r := range logFiles {
					list.AddItem(r, "", 0, nil)
				}
				list.SetBorder(true).SetTitle("Archivos generados").SetBackgroundColor(tcell.ColorDarkBlue)
				okBtn := tview.NewButton("OK").SetSelectedFunc(func() {
					app.SetRoot(flex, true)
				})
				okBtn.SetBackgroundColor(tcell.ColorGreen)
				okBtn.SetLabelColor(tcell.ColorBlack)
				list.SetDoneFunc(func() {
					app.SetRoot(flex, true)
				})
				popup := tview.NewFlex().SetDirection(tview.FlexRow).
					AddItem(tview.NewTextView().SetText("[green]Reporte finalizado![white]\nSolo se muestran los archivos de este escaneo.\n").SetDynamicColors(true), 3, 0, false).
					AddItem(list, 0, 1, true).
					AddItem(okBtn, 3, 0, false)
				popup.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
					if event.Key() == tcell.KeyEsc {
						app.SetRoot(flex, true)
						return nil
					}
					return event
				})
				app.SetRoot(popup, true)
			})
		}()
	})

	if err := app.SetRoot(scanList, true).Run(); err != nil {
		panic(err)
	}
}
