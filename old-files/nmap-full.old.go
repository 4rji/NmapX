package main

import (
    "bufio"
    "bytes"
    "fmt"
    "html"
    "os"
    "os/exec"
    "strings"
    "time"
)

func run(cmd string, args ...string) (string, error) {
    c := exec.Command(cmd, args...)
    var out bytes.Buffer
    c.Stdout = &out
    c.Stderr = &out
    err := c.Run()
    return out.String(), err
}

func checkRoot() {
    if os.Geteuid() != 0 {
        fmt.Println("[!] Run as root.")
        os.Exit(1)
    }
}

func getFirstLine(s string) string {
    for _, line := range strings.Split(s, "\n") {
        if t := strings.TrimSpace(line); t != "" {
            return t
        }
    }
    return ""
}

func main() {
    checkRoot()
    if len(os.Args) < 2 {
        fmt.Println("Usage: ./network_scan_report <CIDR>")
        os.Exit(1)
    }

    target := os.Args[1]
    ts := time.Now().Format("20060102_150405")
    outDir := "recon_" + ts
    os.MkdirAll(outDir, 0755)
    htmlPath := outDir + "/report.html"

    // Interface info
    hostIP, _ := run("sh", "-c", "ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1")
    gateway, _ := run("sh", "-c", "ip route | awk '/default/ {print $3; exit}'")
    networkRaw, _ := run("sh", "-c",
        fmt.Sprintf("ipcalc -n %s %s 2>/dev/null | awk -F= '/Network/ {print $2}'",
            strings.TrimSpace(hostIP), target))
    network := strings.TrimSpace(networkRaw)
    if network == "" {
        network = target
    }

    fmt.Println("\033[1;34m[1] Host discovery\033[0m")
    run("nmap", "-sn", target, "-oG", outDir+"/pingsweep.gnmap")

    // extract live hosts
    fPing, _ := os.Open(outDir + "/pingsweep.gnmap")
    defer fPing.Close()
    fHosts, _ := os.Create(outDir + "/hosts.txt")
    defer fHosts.Close()
    scanner := bufio.NewScanner(fPing)
    for scanner.Scan() {
        line := scanner.Text()
        if strings.HasSuffix(line, "Up") {
            parts := strings.Fields(line)
            if len(parts) >= 2 {
                fHosts.WriteString(parts[1] + "\n")
            }
        }
    }

    // optional arp-scan
    if _, err := exec.LookPath("arp-scan"); err == nil {
        run("arp-scan", "--localnet", "-o", outDir+"/arp.txt")
    }

    // scan mode select
    reader := bufio.NewReader(os.Stdin)
    fmt.Print("\nSelect scan mode:\n 1) Fast   – TCP top 1000\n 2) Medium – TCP/UDP top20 + OS\n 3) Full   – TCP all + UDP + OS\nChoice [1-3] (1): ")
    modeInput, _ := reader.ReadString('\n')
    mode := strings.TrimSpace(modeInput)
    if mode == "" {
        mode = "1"
    }
    var nmapOpts, desc string
    switch mode {
    case "2":
        nmapOpts = "-sS -O -sV -sU --top-ports 20 -T4"
        desc = "Medium"
    case "3":
        nmapOpts = "-sS -sU -O -sV -T4"
        desc = "Full"
    default:
        nmapOpts = "-sS -sV -T4 --top-ports 1000"
        desc = "Fast"
    }

    fmt.Printf("\033[1;34m[2] Port/Service/OS scan – %s\033[0m\n", desc)
    run("bash", "-c",
        fmt.Sprintf("nmap %s -iL %s/hosts.txt -oN %s/ports.nmap -oX %s/ports.xml",
            nmapOpts, outDir, outDir, outDir))

    fmt.Println("\033[1;34m[3] SMB enumeration\033[0m")
    run("nmap", "--script", "smb-enum-shares,smb-os-discovery", "-p", "445",
        "-iL", outDir+"/hosts.txt", "-oN", outDir+"/smb.nmap")

    fmt.Println("\033[1;34m[4] SNMP information\033[0m")
    run("nmap", "-sU", "-p", "161", "--script", "snmp-info",
        "-iL", outDir+"/hosts.txt", "-oN", outDir+"/snmp.nmap")

    fmt.Println("\033[1;34m[5] Vulnerability sweep\033[0m")
    run("nmap", "--script", "vuln", "-iL", outDir+"/hosts.txt", "-oN", outDir+"/vuln.nmap")

    // read outputs
    hostsData, _ := os.ReadFile(outDir + "/hosts.txt")
    portsData, _ := os.ReadFile(outDir + "/ports.nmap")
    smbData, _ := os.ReadFile(outDir + "/smb.nmap")
    snmpData, _ := os.ReadFile(outDir + "/snmp.nmap")
    vulnData, _ := os.ReadFile(outDir + "/vuln.nmap")

    // escape & colorize port states
    escPorts := html.EscapeString(string(portsData))
    escPorts = strings.ReplaceAll(escPorts, " open ", " <span class=\"open\">open</span> ")
    escPorts = strings.ReplaceAll(escPorts, " closed ", " <span class=\"closed\">closed</span> ")
    escPorts = strings.ReplaceAll(escPorts, " filtered ", " <span class=\"filtered\">filtered</span> ")

    escSmb := html.EscapeString(string(smbData))
    escSnmp := html.EscapeString(string(snmpData))
    escVuln := html.EscapeString(string(vulnData))

    // build HTML
    var sb strings.Builder
    sb.WriteString(fmt.Sprintf(`<!DOCTYPE html>
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
.card h3{font-size:.9rem;color:#6c757d;margin-bottom:.25rem;}
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
</head>
<body>
<div class="banner">
  <h1>Network Scan Report</h1>
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
        html.EscapeString(network),
        html.EscapeString(getFirstLine(gateway)),
    ))
    for _, ip := range strings.Split(string(hostsData), "\n") {
        ip = strings.TrimSpace(ip)
        if ip != "" {
            sb.WriteString(fmt.Sprintf("    <li>%s</li>\n", html.EscapeString(ip)))
        }
    }
    sb.WriteString(fmt.Sprintf(`  </ul>
</div>
<div class="section">
  <h2>Port Scan Results</h2>
  <pre>%s</pre>
</div>
<div class="section">
  <h2>SMB Enumeration</h2>
  <pre>%s</pre>
</div>
<div class="section">
  <h2>SNMP Information</h2>
  <pre>%s</pre>
</div>
<div class="section">
  <h2>Vulnerability Scan</h2>
  <pre>%s</pre>
</div>
</body>
</html>
`, escPorts, escSmb, escSnmp, escVuln))

    os.WriteFile(htmlPath, []byte(sb.String()), 0644)
    fmt.Printf("\n\033[1;32m[+] Report generated: %s\033[0m\n", htmlPath)
}
