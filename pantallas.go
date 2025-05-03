// Package main implements a six-screen interactive TUI for building an nmap command dynamically.
// Screens: 1 Host Discovery, 2 Scan Type, 3 Port Selection, 4 Timing, 5 Evasion, 6 NSE Scripts
// Navigate with Left/Right arrows; selections persist and update the command in real time.

package main

import (
	"fmt"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func main() {
	app := tview.NewApplication()

	// Screen 1: Host Discovery options
	hostOpts := []struct{ label, flag, desc string }{
		{"None (-Pn)", "-Pn", "Skip host discovery; treat all targets as online."},
		{"ICMP echo (-PE)", "-PE", "Send ICMP echo request to discover hosts."},
		{"ICMP timestamp (-PP)", "-PP", "Send ICMP timestamp request for host discovery."},
		{"ICMP netmask (-PM)", "-PM", "Send ICMP netmask request to detect hosts."},
		{"TCP SYN (-PS80,443)", "-PS80,443", "Send TCP SYN packets to ports 80 and 443 for ping."},
		{"TCP ACK (-PA80)", "-PA80", "Send TCP ACK packet to port 80 as ping method."},
		{"UDP ping (-PU53)", "-PU53", "Send UDP packet to port 53 to check host."},
		{"SCTP INIT (-PY339)", "-PY339", "Send SCTP INIT packet to port 339 for discovery."},
		{"ARP (-PR)", "-PR", "Use ARP requests for host discovery on local network."},
		{"Traceroute (--traceroute)", "--traceroute", "Perform traceroute to map network path."},
	}

	// Screen 2: Scan Type options
	scanOpts := []struct{ label, flag, desc string }{
		{"SYN Scan (-sS)", "-sS", "Stealth SYN scan."},
		{"TCP Connect (-sT)", "-sT", "Full TCP connect scan."},
		{"UDP Scan (-sU)", "-sU", "UDP scan."},
		{"Version Detect (-sV)", "-sV", "Probe ports for service/version info."},
		{"OS Detect (-O)", "-O", "Determine operating system."},
		{"Aggressive (-A)", "-A", "Enable OS, version, script, and traceroute."},
	}

	// Screen 3: Port Selection
	portOpts := []struct{ label, flag, desc string }{
		{"All ports (-p-)", "-p-", "Scan all ports from 1 to 65535."},
		{"Top 100 (--top-ports 100)", "--top-ports 100", "Scan the 100 most common ports."},
		{"Fast scan (-F)", "-F", "Fast scan using fewer ports (top 100)."},
		{"Custom range (-p)", "-p 1-1024,8080", "Specify custom port ranges or lists."},
		{"Mixed UDP/TCP (-p U:53,T:1-1024)", "-p U:53,T:1-1024", "Mix UDP and TCP ports."},
	}

	// Screen 4: Timing/Performance
	timeOpts := []struct{ label, flag, desc string }{
		{"Paranoid (-T0)", "-T0", "Serial, very slow scan (stealth)."},
		{"Sneaky (-T1)", "-T1", "Slow scan to evade IDS."},
		{"Polite (-T2)", "-T2", "Lower resource usage."},
		{"Normal (-T3)", "-T3", "Default scan speed."},
		{"Aggressive (-T4)", "-T4", "Faster scan, may trigger IDS."},
		{"Insane (-T5)", "-T5", "Fastest scan, very noisy."},
	}

	// Screen 5: Evasion Techniques
	evasionOpts := []struct{ label, flag, desc string }{
		{"Fragment packets (-f)", "-f", "Split packets into smaller fragments."},
		{"Decoys (-D RND:10)", "-D RND:10", "Use decoy IPs to confuse IDS."},
		{"Spoof source IP (-S)", "-S 1.2.3.4", "Set fake source IP address."},
		{"Source port (--source-port)", "--source-port 53", "Use specific source port."},
		{"Data length (--data-length)", "--data-length 50", "Add random data to packets."},
		{"Bad checksum (--badsum)", "--badsum", "Send packets with invalid checksum."},
		{"Randomize hosts (--randomize-hosts)", "--randomize-hosts", "Randomize scan order."},
	}

	// Screen 6: NSE Scripts
	scriptOpts := []struct{ label, flag, desc string }{
		{"firewalk", "--script=firewalk", "Trace firewall filtering rules."},
		{"http-methods", "--script=http-methods", "Check allowed HTTP methods."},
		{"http-waf-detect", "--script=http-waf-detect", "Detect WAF presence."},
		{"http-waf-fingerprint", "--script=http-waf-fingerprint", "Identify WAF vendor."},
		{"ssl-enum-ciphers", "--script=ssl-enum-ciphers", "Enumerate SSL cipher suites."},
		{"smb-vuln-ms17-010", "--script=smb-vuln-ms17-010", "Check MS17-010 vulnerability."},
		{"dns-brute", "--script=dns-brute", "Brute force DNS names."},
		{"ssh-auth-methods", "--script=ssh-auth-methods", "Enumerate SSH auth methods."},
	}

	// Selection state slices for each screen
	hostSel := make([]bool, len(hostOpts))
	scanSel := make([]bool, len(scanOpts))
	portSel := make([]bool, len(portOpts))
	timeSel := make([]bool, len(timeOpts))
	evasionSel := make([]bool, len(evasionOpts))
	scriptSel := make([]bool, len(scriptOpts))

	// Shared command display
	cmdView := tview.NewTextView().SetDynamicColors(true)
	cmdView.SetBorder(true).
		SetTitle("Command").
		SetTitleAlign(tview.AlignLeft)

	// updateCmd rebuilds the nmap command from all selections
	updateCmd := func() {
		cmd := "nmap"
		// Host Discovery
		for i, sel := range hostSel {
			if sel {
				cmd += " " + hostOpts[i].flag
			}
		}
		// Scan Type
		for i, sel := range scanSel {
			if sel {
				cmd += " " + scanOpts[i].flag
			}
		}
		// Ports
		for i, sel := range portSel {
			if sel {
				cmd += " " + portOpts[i].flag
			}
		}
		// Timing
		for i, sel := range timeSel {
			if sel {
				cmd += " " + timeOpts[i].flag
			}
		}
		// Evasion
		for i, sel := range evasionSel {
			if sel {
				cmd += " " + evasionOpts[i].flag
			}
		}
		// NSE Scripts
		for i, sel := range scriptSel {
			if sel {
				cmd += " " + scriptOpts[i].flag
			}
		}
		cmdView.SetText(cmd)
	}
	updateCmd()

	// Build lists for each screen
	hostList := buildList("Host Discovery", hostOpts, hostSel, updateCmd)
	scanList := buildList("Scan Type", scanOpts, scanSel, updateCmd)
	portList := buildList("Port Selection", portOpts, portSel, updateCmd)
	timeList := buildList("Timing/Performance", timeOpts, timeSel, updateCmd)
	evasionList := buildList("Evasion Techniques", evasionOpts, evasionSel, updateCmd)
	scriptList := buildList("NSE Scripts", scriptOpts, scriptSel, updateCmd)

	// Pages container
	pages := tview.NewPages().
		AddPage("disc", hostList, true, true).
		AddPage("scan", scanList, true, false).
		AddPage("port", portList, true, false).
		AddPage("time", timeList, true, false).
		AddPage("evas", evasionList, true, false).
		AddPage("script", scriptList, true, false)

	// Navigation order and corresponding lists
	order := []string{"disc", "scan", "port", "time", "evas", "script"}
	lists := []*tview.List{hostList, scanList, portList, timeList, evasionList, scriptList}
	cur := 0

	// Capture arrow keys to switch screens
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyRight:
			if cur < len(order)-1 {
				cur++
				pages.SwitchToPage(order[cur])
				app.SetFocus(lists[cur])
			}
		case tcell.KeyLeft:
			if cur > 0 {
				cur--
				pages.SwitchToPage(order[cur])
				app.SetFocus(lists[cur])
			}
		}
		return event
	})

	// Layout: command at top, pages below
	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(cmdView, 3, 1, false).
		AddItem(pages, 0, 1, true)

	if err := app.SetRoot(layout, true).Run(); err != nil {
		panic(err)
	}
}

// buildList creates a List primitive with toggleable options
func buildList(title string, opts []struct{ label, flag, desc string }, sel []bool, updateCmd func()) *tview.List {
	list := tview.NewList().ShowSecondaryText(true)
	list.SetBorder(true).
		SetTitle(title).
		SetTitleAlign(tview.AlignLeft)
	for i, opt := range opts {
		idx := i
		list.AddItem(fmt.Sprintf("(%d) %s", i+1, opt.label), opt.desc, rune('1'+i), func() {
			sel[idx] = !sel[idx]
			mark := opt.label
			if sel[idx] {
				mark = fmt.Sprintf("[*] %s", opt.label)
			}
			list.SetItemText(idx, fmt.Sprintf("(%d) %s", i+1, mark), opt.desc)
			updateCmd()
		})
	}
	return list
}
