// Package main implements a six-screen interactive TUI for building an nmap command dynamically.
// Navigate with ←/→ arrows; selections persist and update the command and selected descriptions.
// Layout: vertical split – left half for navigation and command, right half for selected descriptions.

package main

import (
	"fmt"
	"strings"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func main() {
	app := tview.NewApplication()

	// Navigation helper
	helper := tview.NewTextView()
	helper.SetTextAlign(tview.AlignCenter)
	helper.SetText("▶ Use ← and → arrows to navigate screens ◀")
	helper.SetDynamicColors(true)
	helper.SetBorder(true)
	helper.SetTitle("Navigation")
	helper.SetTitleAlign(tview.AlignCenter)

	// Define options per screen
	hostOpts := []struct{ label, flag, desc string }{
		{"None", "-Pn", "Skip host discovery; treat all targets as online."},
		{"ICMP echo", "-PE", "Send ICMP echo request to discover hosts."},
		{"ICMP timestamp", "-PP", "Send ICMP timestamp request for host discovery."},
		{"ICMP netmask", "-PM", "Send ICMP netmask request to detect hosts."},
	}
	scanOpts := []struct{ label, flag, desc string }{
		{"SYN Scan", "-sS", "Stealth SYN scan."},
		{"TCP Connect", "-sT", "Full TCP connect scan."},
		{"UDP Scan", "-sU", "UDP scan."},
	}
	portOpts := []struct{ label, flag, desc string }{
		{"All ports", "-p-", "Scan all ports 1–65535."},
		{"Top 100", "--top-ports 100", "Scan the 100 most common ports."},
		{"Fast scan", "-F", "Fast scan using fewer ports."},
	}
	timeOpts := []struct{ label, flag, desc string }{
		{"Paranoid", "-T0", "Very slow, stealth."},
		{"Sneaky", "-T1", "Slow to evade IDS."},
		{"Normal", "-T3", "Default speed."},
		{"Aggressive", "-T4", "Faster, noisier."},
	}
	evasionOpts := []struct{ label, flag, desc string }{
		{"Fragment", "-f", "Split packets into fragments."},
		{"Decoys", "-D RND:10", "Use random decoy IPs."},
		{"Spoof IP", "-S 1.2.3.4", "Set fake source IP."},
		{"Bad checksum", "--badsum", "Send invalid checksums."},
	}
	scriptOpts := []struct{ label, flag, desc string }{
		{"firewalk", "--script=firewalk", "Trace firewall rules."},
		{"http-methods", "--script=http-methods", "Check allowed HTTP methods."},
		{"dns-brute", "--script=dns-brute", "Brute force DNS names."},
	}

	// Selection state slices
	hostSel := make([]bool, len(hostOpts))
	scanSel := make([]bool, len(scanOpts))
	portSel := make([]bool, len(portOpts))
	timeSel := make([]bool, len(timeOpts))
	evasionSel := make([]bool, len(evasionOpts))
	scriptSel := make([]bool, len(scriptOpts))

	// Command view (below helper in left pane)
	cmdView := tview.NewTextView().SetDynamicColors(true)
	cmdView.SetBorder(true).
		SetTitle("Command").
		SetTitleAlign(tview.AlignLeft)

	// Selected options description view (right pane)
	selDesc := tview.NewTextView().SetDynamicColors(true)
	selDesc.SetBorder(true).
		SetTitle("Selected Options").
		SetTitleAlign(tview.AlignLeft)

	// updateCmd rebuilds the command and descriptions
	updateCmd := func() {
		// Build command
		cmd := "nmap"
		appendFlags := func(opts []struct{ label, flag, desc string }, sel []bool) {
			for i, s := range sel {
				if s { cmd += " " + opts[i].flag }
			}
		}
		appendFlags(hostOpts, hostSel)
		appendFlags(scanOpts, scanSel)
		appendFlags(portOpts, portSel)
		appendFlags(timeOpts, timeSel)
		appendFlags(evasionOpts, evasionSel)
		appendFlags(scriptOpts, scriptSel)
		cmdView.SetText(cmd)

		// Build descriptions
		var b strings.Builder
		dump := func(opts []struct{ label, flag, desc string }, sel []bool) {
			for i, s := range sel {
				if s {
					b.WriteString(fmt.Sprintf("%s (%s): %s\n", opts[i].label, opts[i].flag, opts[i].desc))
				}
			}
		}
		dump(hostOpts, hostSel)
		dump(scanOpts, scanSel)
		dump(portOpts, portSel)
		dump(timeOpts, timeSel)
		dump(evasionOpts, evasionSel)
		dump(scriptOpts, scriptSel)
		selDesc.SetText(b.String())
	}
	updateCmd()

	// Build interactive lists for each screen
	hostList := buildList("📡 Host Discovery", hostOpts, hostSel, updateCmd)
	scanList := buildList("🔍 Scan Type", scanOpts, scanSel, updateCmd)
	portList := buildList("📦 Port Selection", portOpts, portSel, updateCmd)
	timeList := buildList("⏱ Timing", timeOpts, timeSel, updateCmd)
	evasionList := buildList("🛡 Evasion", evasionOpts, evasionSel, updateCmd)
	scriptList := buildList("💻 NSE Scripts", scriptOpts, scriptSel, updateCmd)

	// Pages holding each list
	pages := tview.NewPages().
		AddPage("disc", hostList, true, true).
		AddPage("scan", scanList, true, false).
		AddPage("port", portList, true, false).
		AddPage("time", timeList, true, false).
		AddPage("evas", evasionList, true, false).
		AddPage("script", scriptList, true, false)

	// Navigation order and focusable lists
	order := []string{"disc", "scan", "port", "time", "evas", "script"}
	lists := []*tview.List{hostList, scanList, portList, timeList, evasionList, scriptList}
	cur := 0

	// Capture arrow keys to switch left-pane pages
	app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
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
		return ev
	})

	// Left pane: helper, command, pages
	left := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(helper, 3, 0, false).
		AddItem(cmdView, 3, 0, false).
		AddItem(pages, 0, 1, true)

	// Right pane: descriptions
	right := selDesc

	// Main layout: two columns equally split
	mainFlex := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(left, 0, 1, true).
		AddItem(right, 0, 1, false)

	// Run application
	if err := app.SetRoot(mainFlex, true).Run(); err != nil {
		panic(err)
	}
}

// buildList constructs a toggleable List with options
func buildList(title string, opts []struct{ label, flag, desc string }, sel []bool, update func()) *tview.List {
	list := tview.NewList().ShowSecondaryText(true)
	list.SetBorder(true).SetTitle(title).SetTitleAlign(tview.AlignLeft)
	for i, opt := range opts {
		idx := i
		list.AddItem(fmt.Sprintf("(%d) %s", i+1, opt.label), opt.desc, rune('1'+i), func() {
			sel[idx] = !sel[idx]
			mark := opt.label
			if sel[idx] { mark = fmt.Sprintf("[*] %s", opt.label) }
			list.SetItemText(idx, fmt.Sprintf("(%d) %s", i+1, mark), opt.desc)
			update()
		})
	}
	return list
}
