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
    escapedPorts = strings.ReplaceAll(escapedPorts, " open ", ` <span class="open">open</span> `)
    escapedPorts = strings.ReplaceAll(escapedPorts, " closed ", ` <span class="closed">closed</span> `)
    escapedPorts = strings.ReplaceAll(escapedPorts, " filtered ", ` <span class="filtered">filtered</span> `)

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
    fmt.Printf("\n\033[1;32m[+] Report generated: %s\033[0m\n", htmlPath)
}
