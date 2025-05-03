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
    "strings"
    "time"
    "github.com/rivo/tview"
    "github.com/gdamore/tcell/v2"
    "regexp"
)

func run(cmd string, args ...string) (string, error) {
    command := exec.Command(cmd, args...)
    var out bytes.Buffer
    command.Stdout = &out
    command.Stderr = &out
    err := command.Run()
    return out.String(), err
}

func getFirstLine(out string) string {
    for _, line := range strings.Split(out, "\n") {
        if t := strings.TrimSpace(line); t != "" {
            return t
        }
    }
    return ""
}

func main() {
    if os.Geteuid() != 0 {
        log.Fatal("[!] Run as root.")
    }
    if len(os.Args) < 2 {
        fmt.Println("Usage: ./test_scan_report <CIDR>")
        os.Exit(1)
    }

    // --- UI SETUP ---
    app := tview.NewApplication()
    tview.Styles.PrimitiveBackgroundColor = tcell.ColorDarkBlue
    tview.Styles.ContrastBackgroundColor = tcell.ColorDarkBlue
    tview.Styles.MoreContrastBackgroundColor = tcell.ColorDarkBlue
    tview.Styles.BorderColor = tcell.ColorGreen
    tview.Styles.TitleColor = tcell.ColorGreen
    tview.Styles.GraphicsColor = tcell.ColorLightCyan
    tview.Styles.PrimaryTextColor = tcell.ColorWhite
    tview.Styles.SecondaryTextColor = tcell.ColorLightGrey

    procPane := tview.NewTextView()
    procPane.SetTitle("nmap processes (top)")
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

    // Monitor de procesos nmap usando top | grep nmap
    go func() {
        for {
            out, _ := run("bash", "-c", "top -b -n 1 | grep nmap")
            app.QueueUpdateDraw(func() { procPane.SetText(out) })
            time.Sleep(time.Second)
        }
    }()

    // Monitor tail del archivo ports.nmap
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
                        app.QueueUpdateDraw(func() { tailPane.SetText(content) })
                    }
                }
            } else {
                app.QueueUpdateDraw(func() { tailPane.SetText("") })
            }
            time.Sleep(2 * time.Second)
        }
    }()

    // Redirigir stdout y stderr a logPane
    r, w, _ := os.Pipe()
    os.Stdout = w
    os.Stderr = w
    go func() {
        scanner := bufio.NewScanner(r)
        for scanner.Scan() {
            app.QueueUpdateDraw(func() {
                fmt.Fprintln(logPane, scanner.Text())
            })
        }
    }()

    // Lanzar el escaneo en un goroutine
    go func() {
        target := os.Args[1]
        ts := time.Now().Format("20060102_150405")
        dir := "test_" + ts
        os.MkdirAll(dir, 0755)
        htmlPath := dir + "/report.html"

        hostIP, _ := run("sh", "-c", `ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1`)
        gateway, _ := run("sh", "-c", `ip route | awk '/default/ {print $3; exit}'`)

        fmt.Println("\033[1;34m[1] Host discovery\033[0m")
        run("nmap", "-sn", target, "-oG", dir+"/pingsweep.gnmap")

        f, _ := os.Open(dir + "/pingsweep.gnmap")
        defer f.Close()
        hf, _ := os.Create(dir + "/hosts.txt")
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

        fmt.Println("\033[1;34m[2] Port scan (fast mode)\033[0m")
        run("nmap", "-sS", "-sV", "-T4", "--top-ports", "1000", "-iL", dir+"/hosts.txt", "-oN", dir+"/ports.nmap")

        hostsData, _ := ioutil.ReadFile(dir + "/hosts.txt")
        portsData, _ := ioutil.ReadFile(dir + "/ports.nmap")

        // escape & then color
        escapedPorts := html.EscapeString(string(portsData))
        // Primero protocolos (22/tcp, 53/udp, etc)
        reProto := regexp.MustCompile(`(\d+)/(tcp|udp)`)
        escapedPorts = reProto.ReplaceAllString(escapedPorts, `<span class="proto">$0</span>`)
        // Luego servicios comunes
        reSvc := regexp.MustCompile(`\b(ssh|http|domain|nginx|dnsmasq)\b`)
        escapedPorts = reSvc.ReplaceAllString(escapedPorts, `<span class="svc">$1</span>`)
        // Por último los estados
        reOpen := regexp.MustCompile(`\bopen\b`)
        reClosed := regexp.MustCompile(`\bclosed\b`)
        reFiltered := regexp.MustCompile(`\bfiltered\b`)
        escapedPorts = reOpen.ReplaceAllString(escapedPorts, `<span class="open">open</span>`)
        escapedPorts = reClosed.ReplaceAllString(escapedPorts, `<span class="closed">closed</span>`)
        escapedPorts = reFiltered.ReplaceAllString(escapedPorts, `<span class="filtered">filtered</span>`)

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
            html.EscapeString(getFirstLine(hostIP)),
            html.EscapeString(target),
            html.EscapeString(getFirstLine(gateway)),
        )

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

        ioutil.WriteFile(htmlPath, []byte(htmlContent), 0644)
        // Mostrar popup solo con el reporte generado y los logs del escaneo actual
        app.QueueUpdateDraw(func() {
            // Archivos relevantes del escaneo actual
            var logFiles []string
            files, _ := ioutil.ReadDir(dir)
            for _, f := range files {
                if strings.HasSuffix(f.Name(), ".nmap") || strings.HasSuffix(f.Name(), ".gnmap") || f.Name() == "hosts.txt" {
                    logFiles = append(logFiles, dir+"/"+f.Name())
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

    if err := app.SetRoot(flex, true).Run(); err != nil {
        panic(err)
    }
}

