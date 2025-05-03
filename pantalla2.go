package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// OpenAI endpoint
const apiURL = "https://api.openai.com/v1/chat/completions"

// Chat API payload types
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type RequestBody struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

type Choice struct {
	Message Message `json:"message"`
}

type ResponseBody struct {
	Choices []Choice `json:"choices"`
}

func main() {
	var runAfter bool // execute after TUI
	var finalCmd string

	app := tview.NewApplication()

	// Navigation helper
	helper := tview.NewTextView()
	helper.SetTextAlign(tview.AlignCenter)
	helper.SetText("◀ ←/→ navigate | 'x' explain | 'E' run & exit ▶")
	helper.SetBorder(true)
	helper.SetTitle("Navigation")
	helper.SetTitleAlign(tview.AlignCenter)

	// Options (sample two screens)
	hostOpts := []struct{ label, flag, desc string }{
		{"None", "-Pn", "Skip host discovery"},
		{"ICMP echo", "-PE", "Send ICMP echo"},
	}
	scanOpts := []struct{ label, flag, desc string }{
		{"SYN", "-sS", "Stealth SYN scan"},
		{"Connect", "-sT", "TCP connect scan"},
	}

	hostSel := make([]bool, len(hostOpts))
	scanSel := make([]bool, len(scanOpts))

	// Views
	cmdView := tview.NewTextView().SetDynamicColors(true)
	cmdView.SetBorder(true).SetTitle("Command")

	selDesc := tview.NewTextView().SetDynamicColors(true)
	selDesc.SetBorder(true).SetTitle("Selected")

	detail := tview.NewTextView().SetDynamicColors(true)
	detail.SetBorder(true).SetTitle("Details")

	// Update function
	update := func() {
		parts := []string{"nmap"}
		for i, s := range hostSel {
			if s {
				parts = append(parts, hostOpts[i].flag)
			}
		}
		for i, s := range scanSel {
			if s {
				parts = append(parts, scanOpts[i].flag)
			}
		}
		cmd := strings.Join(parts, " ")
		cmdView.SetText(cmd)

		var b strings.Builder
		for i, s := range hostSel {
			if s {
				fmt.Fprintf(&b, "%s (%s)\n", hostOpts[i].label, hostOpts[i].flag)
			}
		}
		for i, s := range scanSel {
			if s {
				fmt.Fprintf(&b, "%s (%s)\n", scanOpts[i].label, scanOpts[i].flag)
			}
		}
		selDesc.SetText(b.String())
	}
	update()

	// Build lists
	hostList := makeList("📡 Host", hostOpts, hostSel, update)
	scanList := makeList("🔍 Scan", scanOpts, scanSel, update)

	// Pages
	pages := tview.NewPages().
		AddPage("host", hostList, true, true).
		AddPage("scan", scanList, true, false)

	order := []string{"host", "scan"}
	lists := []*tview.List{hostList, scanList}
	cur := 0

	// Input capture
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
			explain(cmdView, detail)
		case ev.Key() == tcell.KeyRune && ev.Rune() == 'E':
			finalCmd := cmdView.GetText(true)
			app.Stop()
			// Ejecutar el comando en la terminal real
			args := strings.Fields(finalCmd)
			if len(args) > 0 {
				// Reemplaza el proceso actual por el comando generado
				err := syscall.Exec("/usr/bin/env", append([]string{"env"}, args...), os.Environ())
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error al ejecutar el comando:", err)
					os.Exit(1)
				}
			}
		}
		return ev
	})

	// Layout
	left := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(helper, 3, 0, false).
		AddItem(cmdView, 3, 0, false).
		AddItem(pages, 0, 1, true)

	right := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(selDesc, 0, 1, false).
		AddItem(detail, 0, 1, false)

	main := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(left, 0, 1, true).
		AddItem(right, 0, 1, false)

	if err := app.SetRoot(main, true).Run(); err != nil {
		panic(err)
	}

	// After TUI exit, run external command if flagged
	if runAfter {
		shellCmd := fmt.Sprintf("nmapx '%s'", finalCmd)
		exec.Command("sh", "-c", shellCmd).Run()
	}
}

// makeList builds a selectable list
func makeList(title string, opts []struct{ label, flag, desc string }, sel []bool, upd func()) *tview.List {
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
			upd()
		})
	}
	return l
}

// explain sends the command to OpenAI and writes the reply into detail pane
func explain(cmdView *tview.TextView, detail *tview.TextView) {
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		detail.SetText("OPENAI_API_KEY not set")
		return
	}
	cmd := cmdView.GetText(true)
	msgs := []Message{
		{Role: "system", Content: "Explain briefly what this nmap command does."},
		{Role: "user", Content: cmd},
	}
	body := RequestBody{Model: "gpt-4o-mini", Messages: msgs}
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", apiURL, bytes.NewBuffer(data))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		detail.SetText(err.Error())
		return
	}
	defer resp.Body.Close()
	var rb ResponseBody
	json.NewDecoder(resp.Body).Decode(&rb)
	if len(rb.Choices) > 0 {
		detail.SetText(rb.Choices[0].Message.Content)
	} else {
		detail.SetText("No explanation")
	}
}
