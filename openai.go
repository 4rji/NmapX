package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"

	"github.com/rivo/tview"
)

// API endpoint
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

func Explain(cmdView *tview.TextView, detail *tview.TextView) {
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		detail.SetText("OPENAI_API_KEY not set")
		return
	}

	cmd := cmdView.GetText(true)
	body := RequestBody{
		Model: "gpt-4o-mini",
		Messages: []Message{
			{"system", "Explain briefly what this nmap command does."},
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
