package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// OpenAI API endpoint
const apiURL = "https://api.openai.com/v1/chat/completions"

// ---------- OpenAI payload types ----------

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

//-------------------------------------------

func main() {
	var runAfter bool   // flag to execute nmapx after TUI
	var finalCmd string // command to run after exit

	// Get target host from command line arguments
	target := "localhost" // default target
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	app := tview.NewApplication()

	// Configurar estilos globales
	tview.Styles.PrimitiveBackgroundColor = tcell.ColorDarkBlue
	tview.Styles.ContrastBackgroundColor = tcell.ColorDarkBlue
	tview.Styles.MoreContrastBackgroundColor = tcell.ColorDarkBlue
	tview.Styles.BorderColor = tcell.ColorGreen
	tview.Styles.TitleColor = tcell.ColorGreen
	tview.Styles.GraphicsColor = tcell.ColorLightCyan
	tview.Styles.PrimaryTextColor = tcell.ColorWhite
	tview.Styles.SecondaryTextColor = tcell.ColorLightGrey

	// ========== Helper banner ===========
	helper := tview.NewTextView()
	helper.SetTextAlign(tview.AlignCenter)
	helper.SetBorder(true).SetTitle("Navigation")
	helper.SetBackgroundColor(tcell.ColorDarkBlue)
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
	cmdView.SetBackgroundColor(tcell.ColorDarkBlue)

	selDesc := tview.NewTextView()
	selDesc.SetDynamicColors(true)
	selDesc.SetBorder(true)
	selDesc.SetTitle("Selected")
	selDesc.SetBackgroundColor(tcell.ColorDarkBlue)

	detail := tview.NewTextView()
	detail.SetDynamicColors(true)
	detail.SetBorder(true)
	detail.SetTitle("Explanation")
	detail.SetBackgroundColor(tcell.ColorDarkBlue)

	// Variable para el comando limpio
	var lastCmdStr string

	// Botón Copy
	copyBtn := tview.NewButton("Copy").SetSelectedFunc(func() {
		err := copyToClipboard(lastCmdStr)
		if err == nil {
			cmdView.SetTitle("Command (Copied!)")
		} else {
			cmdView.SetTitle("Command (Copy failed)")
		}
		go func() {
			time.Sleep(1 * time.Second)
			app.QueueUpdateDraw(func() {
				cmdView.SetTitle("Command")
			})
		}()
	})
	copyBtn.SetBorder(true)
	copyBtn.SetBackgroundColor(tcell.ColorDarkBlue)

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
		parts = append(parts, target) // Add target host to the command
		cmdStr := strings.Join(parts, " ")
		lastCmdStr = cmdStr // Guardar el comando limpio para copiar
		// Simular grosor: repetir y rodear con ▓
		decorated := fmt.Sprintf("▓ %s ▓\n▓ %s ▓", cmdStr, cmdStr)
		cmdView.SetText(decorated)

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

	// Variable para alternar el foco
	focusOnCmdBar := false

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
	hostList := makeList("   📡 Host   ", hostOpts, hostSel)
	scanList := makeList("   🔍 Scan   ", scanOpts, scanSel)
	portList := makeList("   📦 Ports   ", portOpts, portSel)
	timeList := makeList("   ⏱ Timing   ", timeOpts, timeSel)
	evasList := makeList("   🛡 Evasion   ", evasionOpts, evasionSel)
	nseList := makeList("   💻 NSE   ", scriptOpts, scriptSel)

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

	// input capture mejorado: Tab cambia entre UI principal y barra de comando
	app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyTAB {
			if !focusOnCmdBar {
				app.SetFocus(copyBtn)
				focusOnCmdBar = true
			} else {
				app.SetFocus(lists[cur])
				focusOnCmdBar = false
			}
			return nil
		}
		switch {
		case ev.Key() == tcell.KeyRight && cur < len(order)-1 && !focusOnCmdBar:
			cur++
			pages.SwitchToPage(order[cur])
			app.SetFocus(lists[cur])
		case ev.Key() == tcell.KeyLeft && cur > 0 && !focusOnCmdBar:
			cur--
			pages.SwitchToPage(order[cur])
			app.SetFocus(lists[cur])
		case ev.Key() == tcell.KeyRune && ev.Rune() == 'x' && !focusOnCmdBar:
			explain(cmdView, detail)
		case ev.Key() == tcell.KeyRune && ev.Rune() == 'E' && !focusOnCmdBar:
			runAfter = true
			finalCmd = lastCmdStr
			app.Stop()
		}
		return ev
	})

	// layout principal: body arriba, barra de comando abajo
	left := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(helper, 3, 0, false).
		AddItem(pages, 0, 1, true)
	left.SetBackgroundColor(tcell.ColorDarkBlue)

	right := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(selDesc, 0, 4, false).
		AddItem(detail, 0, 8, false)
	right.SetBackgroundColor(tcell.ColorDarkBlue)

	mainBody := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(left, 0, 1, true).
		AddItem(right, 0, 1, false)
	mainBody.SetBackgroundColor(tcell.ColorDarkBlue)

	// Barra inferior: comando + botón Copy
	cmdBar := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(cmdView, 0, 5, false).
		AddItem(copyBtn, 12, 0, false)
	cmdBar.SetBackgroundColor(tcell.ColorDarkBlue)

	rootFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(mainBody, 0, 1, true).
		AddItem(cmdBar, 3, 0, false)
	rootFlex.SetBackgroundColor(tcell.ColorDarkBlue)

	if err := app.SetRoot(rootFlex, true).Run(); err != nil {
		panic(err)
	}

	if runAfter {
		// Split the command into parts and execute directly
		cmdParts := strings.Split(finalCmd, " ")
		cmd := exec.Command(cmdParts[0], cmdParts[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
	}
}

func explain(cmdView *tview.TextView, detail *tview.TextView) {
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		detail.SetText("OPENAI_API_KEY not set")
		return
	}

	cmd := cmdView.GetText(true)
	body := RequestBody{
		Model: "gpt-4o-mini",
		Messages: []Message{
			{"system", "Summarize what this nmap command does in a security context. Be brief and skip any mention that it's an nmap command. Don't explain individual flags. Just describe the overall action and intent. Check if the command is valid or has conflicting options. If it's invalid, suggest a corrected version."},
			{"user", cmd},
		},
	}

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
	if err := json.NewDecoder(resp.Body).Decode(&rb); err != nil {
		detail.SetText(err.Error())
		return
	}

	if len(rb.Choices) > 0 {
		detail.SetText(rb.Choices[0].Message.Content)
	} else {
		detail.SetText("No response from API")
	}
}

// copyToClipboard copia el texto al portapapeles en Mac y Linux
func copyToClipboard(text string) error {
	// Intentar pbcopy (Mac)
	cmd := "pbcopy"
	if _, err := os.Stat("/usr/bin/pbcopy"); err == nil {
		c := execCommand(cmd)
		c.Stdin = strings.NewReader(text)
		return c.Run()
	}
	// Intentar xclip (Linux)
	cmd = "xclip"
	if _, err := os.Stat("/usr/bin/xclip"); err == nil {
		c := execCommand(cmd, "-selection", "clipboard")
		c.Stdin = strings.NewReader(text)
		return c.Run()
	}
	// Intentar xsel (Linux)
	cmd = "xsel"
	if _, err := os.Stat("/usr/bin/xsel"); err == nil {
		c := execCommand(cmd, "--clipboard", "--input")
		c.Stdin = strings.NewReader(text)
		return c.Run()
	}
	return fmt.Errorf("No clipboard utility found (pbcopy, xclip, xsel)")
}

// execCommand es un wrapper para exec.Command
func execCommand(name string, arg ...string) *exec.Cmd {
	return exec.Command(name, arg...)
}
