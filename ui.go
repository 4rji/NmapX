package main

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// Estructuras para mantener el estado de la aplicación
type AppState struct {
	app               *tview.Application
	procPane          *tview.TextView
	tailPane          *tview.TextView
	logPane           *tview.TextView
	flex              *tview.Flex
	target            string
	scanDir           string
	htmlPath          string
	selectedNmapArgs  []string
	selectedExtraCmds []string
}

// SetupUI configura la UI de la aplicación
func SetupUI() *AppState {
	state := &AppState{}

	// Crear aplicación tview
	state.app = tview.NewApplication()

	// Configurar estilos globales
	tview.Styles.PrimitiveBackgroundColor = tcell.ColorDarkBlue
	tview.Styles.ContrastBackgroundColor = tcell.ColorDarkBlue
	tview.Styles.MoreContrastBackgroundColor = tcell.ColorDarkBlue
	tview.Styles.BorderColor = tcell.ColorGreen
	tview.Styles.TitleColor = tcell.ColorGreen
	tview.Styles.GraphicsColor = tcell.ColorLightCyan
	tview.Styles.PrimaryTextColor = tcell.ColorWhite
	tview.Styles.SecondaryTextColor = tcell.ColorLightGrey

	// Crear paneles
	state.procPane = tview.NewTextView()
	state.procPane.SetTitle("nmap processes (top)")
	state.procPane.SetBorder(true)
	state.procPane.SetBackgroundColor(tcell.ColorDarkBlue)

	state.tailPane = tview.NewTextView()
	state.tailPane.SetTitle("ports.nmap (tail)")
	state.tailPane.SetBorder(true)
	state.tailPane.SetBackgroundColor(tcell.ColorDarkBlue)

	state.logPane = tview.NewTextView()
	state.logPane.SetTitle("scan log")
	state.logPane.SetBorder(true)
	state.logPane.SetBackgroundColor(tcell.ColorDarkBlue)
	state.logPane.SetChangedFunc(func() {
		state.logPane.ScrollToEnd()
		state.app.Draw()
	})

	// Crear layout
	leftFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(state.procPane, 0, 1, false).
		AddItem(state.logPane, 0, 1, false)
	leftFlex.SetBackgroundColor(tcell.ColorDarkBlue)

	state.flex = tview.NewFlex().
		AddItem(leftFlex, 0, 1, false).
		AddItem(state.tailPane, 0, 2, true)
	state.flex.SetBackgroundColor(tcell.ColorDarkBlue)

	return state
}
