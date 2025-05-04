package main

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// ShowNmapTUI displays the TUI interface for customizing Nmap commands
func ShowNmapTUI(state *AppState) string {
	app := state.app

	// ========== Helper banner ===========
	helper := tview.NewTextView()
	helper.SetTextAlign(tview.AlignCenter)
	helper.SetBorder(true).SetTitle("Navigation")
	helper.SetText("◀ ←/→ navigate | 'x' explain | 'E' run & exit ▶")

	// ========== Option sets for 6 screens ==========
	hostOpts := []struct{ label, flag, desc string }{
		{"None", "-Pn", "Skip host discovery; assume hosts up"},
		{"ICMP echo", "-PE", "ICMP echo ping"},
		{"ICMP timestamp", "-PP", "ICMP timestamp ping"},
		{"TCP SYN 80,443", "-PS80,443", "SYN ping to ports 80/443"},
		{"UDP 53", "-PU53", "UDP ping to port 53"},
	}
	scanOpts := []struct{ label, flag, desc string }{
		{"SYN", "-sS", "Stealth SYN scan"},
		{"Connect", "-sT", "TCP connect scan"},
		{"UDP", "-sU", "UDP scan"},
		{"Version", "-sV", "Service/version detection"},
		{"Aggressive", "-A", "OS, version, scripts, traceroute"},
	}
	portOpts := []struct{ label, flag, desc string }{
		{"All ports", "-p-", "1-65535"},
		{"Top 100", "--top-ports 100", "Top 100 common"},
		{"Fast", "-F", "Fast limited"},
		{"Custom 1-1024", "-p 1-1024", "Range 1-1024"},
	}
	timeOpts := []struct{ label, flag, desc string }{
		{"Normal", "-T3", "Default timing"},
		{"Aggressive", "-T4", "Faster"},
		{"Insane", "-T5", "Very fast"},
	}
	evasionOpts := []struct{ label, flag, desc string }{
		{"Fragment", "-f", "Fragment packets"},
		{"Decoys", "-D RND:10", "Random decoy IPs"},
		{"Spoof IP", "-S 1.2.3.4", "Fake source IP"},
	}
	scriptOpts := []struct{ label, flag, desc string }{
		{"firewalk", "--script=firewalk", "Trace firewall rules"},
		{"ssl‑ciphers", "--script=ssl-enum-ciphers", "Enumerate SSL ciphers"},
		{"dns‑brute", "--script=dns-brute", "Brute‑force subdomains"},
	}

	// selection slices
	hostSel := make([]bool, len(hostOpts))
	scanSel := make([]bool, len(scanOpts))
	portSel := make([]bool, len(portOpts))
	timeSel := make([]bool, len(timeOpts))
	evasionSel := make([]bool, len(evasionOpts))
	scriptSel := make([]bool, len(scriptOpts))

	// -------- Views --------
	cmdView := tview.NewTextView()
	cmdView.SetDynamicColors(true)
	cmdView.SetBorder(true)
	cmdView.SetTitle("Command")

	selDesc := tview.NewTextView()
	selDesc.SetDynamicColors(true)
	selDesc.SetBorder(true)
	selDesc.SetTitle("Selected")

	detail := tview.NewTextView()
	detail.SetDynamicColors(true)
	detail.SetBorder(true)
	detail.SetTitle("Details")

	// -------- Update function --------
	update := func() {
		parts := []string{"nmap"}
		add := func(opts []struct{ label, flag, desc string }, sel []bool) {
			for i, s := range sel {
				if s {
					parts = append(parts, opts[i].flag)
				}
			}
		}
		add(hostOpts, hostSel)
		add(scanOpts, scanSel)
		add(portOpts, portSel)
		add(timeOpts, timeSel)
		add(evasionOpts, evasionSel)
		add(scriptOpts, scriptSel)
		cmdView.SetText(strings.Join(parts, " "))

		var b strings.Builder
		dump := func(opts []struct{ label, flag, desc string }, sel []bool) {
			for i, s := range sel {
				if s {
					fmt.Fprintf(&b, "%s (%s)\n", opts[i].label, opts[i].flag)
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
	update()

	// -------- List builder --------
	makeList := func(title string, opts []struct{ label, flag, desc string }, sel []bool) *tview.List {
		l := tview.NewList().ShowSecondaryText(true)
		l.SetBorder(true).SetTitle(title)
		for i, o := range opts {
			idx := i
			l.AddItem(fmt.Sprintf("(%d) %s", i+1, o.label), o.desc, rune('1'+i), func() {
				sel[idx] = !sel[idx]
				mark := o.label
				if sel[idx] {
					mark = "[*] " + o.label
				}
				l.SetItemText(idx, fmt.Sprintf("(%d) %s", i+1, mark), o.desc)
				update()
			})
		}
		return l
	}

	// create lists
	hostList := makeList("📡 Host", hostOpts, hostSel)
	scanList := makeList("🔍 Scan", scanOpts, scanSel)
	portList := makeList("📦 Ports", portOpts, portSel)
	timeList := makeList("⏱ Timing", timeOpts, timeSel)
	evasList := makeList("🛡 Evasion", evasionOpts, evasionSel)
	nseList := makeList("💻 NSE", scriptOpts, scriptSel)

	// pages
	pages := tview.NewPages().
		AddPage("host", hostList, true, true).
		AddPage("scan", scanList, true, false).
		AddPage("port", portList, true, false).
		AddPage("time", timeList, true, false).
		AddPage("evas", evasList, true, false).
		AddPage("nse", nseList, true, false)

	order := []string{"host", "scan", "port", "time", "evas", "nse"}
	lists := []*tview.List{hostList, scanList, portList, timeList, evasList, nseList}
	cur := 0

	var finalCmd string

	// input capture
	app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch {
		case ev.Key() == tcell.KeyRight && cur < len(order)-1:
			cur++
			pages.SwitchToPage(order[cur])
			app.SetFocus(lists[cur])
		case ev.Key() == tcell.KeyLeft && cur > 0:
			cur--
			pages.SwitchToPage(order[cur])
			app.SetFocus(lists[cur])
		case ev.Key() == tcell.KeyRune && ev.Rune() == 'x':
			Explain(cmdView, detail)
		case ev.Key() == tcell.KeyRune && ev.Rune() == 'E':
			finalCmd = cmdView.GetText(true)
			app.Stop()
		}
		return ev
	})

	// layout
	left := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(helper, 3, 0, false).
		AddItem(cmdView, 3, 0, false).
		AddItem(pages, 0, 1, true)
	right := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(selDesc, 0, 1, false).
		AddItem(detail, 0, 1, false)
	root := tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(left, 0, 1, true).
		AddItem(right, 0, 1, false)

	app.SetRoot(root, true)
	if err := app.Run(); err != nil {
		panic(err)
	}

	return finalCmd
}
