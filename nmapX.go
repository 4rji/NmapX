// Package main implements a six-screen interactive TUI for building and executing an nmap command.
// Navigate with ←/→ arrows; selections persist and update the command and selected descriptions.
// Press 'x' to execute the assembled nmap command and view output in the Details pane.

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

// OpenAI API endpoint and types
const apiURL = "https://api.openai.com/v1/chat/completions"

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

// Variable global para el comando limpio
var lastCmdStr string

func main() {
	app := tview.NewApplication()

	// Declarar vistas principales al inicio para que estén disponibles en todo el scope
	cmdView := tview.NewTextView().SetDynamicColors(true)
	selDesc := tview.NewTextView().SetDynamicColors(true)
	detailView := tview.NewTextView().SetDynamicColors(true)

	cmdView.SetBorder(true).SetTitle("Command").SetTitleAlign(tview.AlignLeft)
	cmdView.SetBackgroundColor(tcell.ColorDarkBlue)
	cmdView.SetWrap(false)

	selDesc.SetBorder(true).SetTitle("Selected Options").SetTitleAlign(tview.AlignLeft)
	selDesc.SetBackgroundColor(tcell.ColorDarkBlue)

	detailView.SetBorder(true).SetTitle("Explanation").SetTitleAlign(tview.AlignLeft)
	detailView.SetBackgroundColor(tcell.ColorDarkBlue)

	// Configurar estilos globales
	tview.Styles.PrimitiveBackgroundColor = tcell.ColorDarkBlue
	tview.Styles.ContrastBackgroundColor = tcell.ColorDarkBlue
	tview.Styles.MoreContrastBackgroundColor = tcell.ColorDarkBlue
	tview.Styles.BorderColor = tcell.ColorGreen
	tview.Styles.TitleColor = tcell.ColorGreen
	tview.Styles.GraphicsColor = tcell.ColorLightCyan
	tview.Styles.PrimaryTextColor = tcell.ColorWhite
	tview.Styles.SecondaryTextColor = tcell.ColorLightGrey

	// Navigation helper
	helper := tview.NewTextView()
	helper.SetTextAlign(tview.AlignCenter)
	helper.SetText("◀ Use ←/→ to switch screens — press 'x' to send to explain ▶")
	helper.SetBorder(true)
	helper.SetTitle("Navigation")
	helper.SetTitleAlign(tview.AlignCenter)
	helper.SetBackgroundColor(tcell.ColorDarkBlue)

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

	// Selection state
	hostSel := make([]bool, len(hostOpts))
	scanSel := make([]bool, len(scanOpts))
	portSel := make([]bool, len(portOpts))
	timeSel := make([]bool, len(timeOpts))
	evasionSel := make([]bool, len(evasionOpts))
	scriptSel := make([]bool, len(scriptOpts))

	// Botón Copy (modificado para copiar solo el comando limpio)
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

	// updateCmd rebuilds command and selected descriptions
	updateCmd := func() {
		cmd := []string{"nmap"}
		addFlags := func(opts []struct{ label, flag, desc string }, sel []bool) {
			for i, s := range sel {
				if s {
					cmd = append(cmd, opts[i].flag)
				}
			}
		}
		addFlags(hostOpts, hostSel)
		addFlags(scanOpts, scanSel)
		addFlags(portOpts, portSel)
		addFlags(timeOpts, timeSel)
		addFlags(evasionOpts, evasionSel)
		addFlags(scriptOpts, scriptSel)
		cmdStr := strings.Join(cmd, " ")
		lastCmdStr = cmdStr // Guardar el comando limpio para copiar
		// Simular grosor: repetir y rodear con ▓
		decorated := fmt.Sprintf("▓ %s ▓\n▓ %s ▓", cmdStr, cmdStr)
		cmdView.SetText(decorated)

		// descriptions
		var b strings.Builder
		addDescs := func(opts []struct{ label, flag, desc string }, sel []bool) {
			for i, s := range sel {
				if s {
					b.WriteString(fmt.Sprintf("%s %s: %s\n", opts[i].flag, opts[i].label, opts[i].desc))
				}
			}
		}
		addDescs(hostOpts, hostSel)
		addDescs(scanOpts, scanSel)
		addDescs(portOpts, portSel)
		addDescs(timeOpts, timeSel)
		addDescs(evasionOpts, evasionSel)
		addDescs(scriptOpts, scriptSel)
		selDesc.SetText(b.String())
	}
	updateCmd()

	// Build lists for screens
	hostList := buildList("📡 Host Discovery", hostOpts, hostSel, updateCmd)
	scanList := buildList("🔍 Scan Type", scanOpts, scanSel, updateCmd)
	portList := buildList("📦 Port Selection", portOpts, portSel, updateCmd)
	timeList := buildList("⏱ Timing", timeOpts, timeSel, updateCmd)
	evasionList := buildList("🛡 Evasion", evasionOpts, evasionSel, updateCmd)
	scriptList := buildList("💻 NSE Scripts", scriptOpts, scriptSel, updateCmd)

	// Pages with lists (left pane middle)
	pages := tview.NewPages().
		AddPage("disc", hostList, true, true).
		AddPage("scan", scanList, true, false).
		AddPage("port", portList, true, false).
		AddPage("time", timeList, true, false).
		AddPage("evas", evasionList, true, false).
		AddPage("script", scriptList, true, false)

	// Navigation order & focusable lists
	order := []string{"disc", "scan", "port", "time", "evas", "script"}
	lists := []*tview.List{hostList, scanList, portList, timeList, evasionList, scriptList}
	cur := 0

	// Variable para alternar el foco
	focusOnCmdBar := false

	// Arrow navigation + execute on 'x' + Tab para cambiar foco
	app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyTAB {
			if !focusOnCmdBar {
				app.SetFocus(copyBtn)
				focusOnCmdBar = true
			} else {
				app.SetFocus(lists[cur])
				focusOnCmdBar = false
			}
			return nil // Consumir el evento
		}
		if !focusOnCmdBar {
			if ev.Key() == tcell.KeyRight {
				if cur < len(order)-1 {
					cur++
					pages.SwitchToPage(order[cur])
					app.SetFocus(lists[cur])
				}
			} else if ev.Key() == tcell.KeyLeft {
				if cur > 0 {
					cur--
					pages.SwitchToPage(order[cur])
					app.SetFocus(lists[cur])
				}
			} else if ev.Key() == tcell.KeyRune && ev.Rune() == 'x' {
				// Explain assembled nmap command via OpenAI
				apiKey := os.Getenv("OPENAI_API_KEY")
				if apiKey == "" {
					detailView.SetText("Error: OPENAI_API_KEY not set")
				} else {
					cmdStr := cmdView.GetText(true)
					// Build chat messages
					msgs := []Message{
						{Role: "system", Content: "Summarize what this nmap command does in a security context. Be brief and skip any mention that it's an nmap command. Don't explain individual flags. Just describe the overall action and intent. Check if the command is valid or has conflicting options. If it's invalid, suggest a corrected version."},
						{Role: "user", Content: cmdStr},
					}
					reqBody := RequestBody{Model: "gpt-4o-mini", Messages: msgs}
					data, _ := json.Marshal(reqBody)
					req, _ := http.NewRequest("POST", apiURL, bytes.NewBuffer(data))
					req.Header.Set("Authorization", "Bearer "+apiKey)
					req.Header.Set("Content-Type", "application/json")
					resp, err := http.DefaultClient.Do(req)
					if err != nil {
						detailView.SetText(fmt.Sprintf("Request error: %v", err))
					} else {
						defer resp.Body.Close()
						var rBody ResponseBody
						json.NewDecoder(resp.Body).Decode(&rBody)
						if len(rBody.Choices) > 0 {
							detailView.SetText(rBody.Choices[0].Message.Content)
						} else {
							detailView.SetText("No explanation received.")
						}
					}
				}
			}
		}
		return ev
	})

	// Left pane: helper, pages (ya no incluye cmdView)
	left := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(helper, 3, 0, false).
		AddItem(pages, 0, 1, true)
	left.SetBackgroundColor(tcell.ColorDarkBlue)

	// Right pane: dos mitades, pero ahora Explanation (detailView) es 20% más alto
	right := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(selDesc, 0, 4, false).
		AddItem(detailView, 0, 8, false)
	right.SetBackgroundColor(tcell.ColorDarkBlue)

	// Main layout: dos columnas arriba, barra de comando abajo
	mainBody := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(left, 0, 1, true).
		AddItem(right, 0, 1, false)
	mainBody.SetBackgroundColor(tcell.ColorDarkBlue)

	// Barra inferior: comando + botón Copy
	cmdBar := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(cmdView, 0, 5, false).
		AddItem(copyBtn, 12, 0, false)
	cmdBar.SetBackgroundColor(tcell.ColorDarkBlue)

	// Layout final: todo el body arriba, barra de comando abajo
	rootFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(mainBody, 0, 1, true).
		AddItem(cmdBar, 3, 0, false)
	rootFlex.SetBackgroundColor(tcell.ColorDarkBlue)

	if err := app.SetRoot(rootFlex, true).Run(); err != nil {
		panic(err)
	}
}

// buildList constructs a toggleable list
func buildList(title string, opts []struct{ label, flag, desc string }, sel []bool, update func()) *tview.List {
	list := tview.NewList().ShowSecondaryText(true)
	list.SetBorder(true).SetTitle(title).SetTitleAlign(tview.AlignLeft)
	for i, opt := range opts {
		idx := i
		list.AddItem(fmt.Sprintf("(%d) %s", i+1, opt.label), opt.desc, rune('1'+i), func() {
			sel[idx] = !sel[idx]
			mark := opt.label
			if sel[idx] {
				mark = fmt.Sprintf("[*] %s", opt.label)
			}
			list.SetItemText(idx, fmt.Sprintf("(%d) %s", i+1, mark), opt.desc)
			update()
		})
	}
	return list
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
