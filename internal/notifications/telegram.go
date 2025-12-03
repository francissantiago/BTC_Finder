package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// TelegramNotifier sends notifications via Telegram Bot API
type TelegramNotifier struct {
	botToken string
	chatID   string
	client   *http.Client
}

// NewTelegramNotifier creates a new Telegram notifier
func NewTelegramNotifier(botToken, chatID string) *TelegramNotifier {
	return &TelegramNotifier{
		botToken: botToken,
		chatID:   chatID,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SendMatchAlert sends a notification about found private key
func (t *TelegramNotifier) SendMatchAlert(address, privateKey, targetAddress string) error {
	if t.botToken == "" || t.chatID == "" {
		return fmt.Errorf("telegram bot token or chat id not configured")
	}

	message := fmt.Sprintf(
		"🎉 *BTC Match Found!*\n\n" +
			"*Target Address:* `%s`\n" +
			"*Private Key:* `%s`\n" +
			"*Derived Address:* `%s`\n" +
			"*Timestamp:* %s",
		targetAddress,
		privateKey,
		address,
		time.Now().Format("2006-01-02 15:04:05 MST"),
	)

	return t.sendMessage(message, "MarkdownV2")
}

// SendJobAlert sends a notification about job status
func (t *TelegramNotifier) SendJobAlert(jobID, seedID, status string, keysChecked int64) error {
	if t.botToken == "" || t.chatID == "" {
		return fmt.Errorf("telegram bot token or chat id not configured")
	}

	message := fmt.Sprintf(
		"ℹ️ *Job Status Update*\n\n" +
			"*Job ID:* `%s`\n" +
			"*Seed ID:* `%s`\n" +
			"*Status:* %s\n" +
			"*Keys Checked:* %d\n" +
			"*Timestamp:* %s",
		jobID,
		seedID,
		status,
		keysChecked,
		time.Now().Format("2006-01-02 15:04:05 MST"),
	)

	return t.sendMessage(message, "MarkdownV2")
}

// SendErrorAlert sends an error notification
func (t *TelegramNotifier) SendErrorAlert(errorMessage string) error {
	if t.botToken == "" || t.chatID == "" {
		return fmt.Errorf("telegram bot token or chat id not configured")
	}

	message := fmt.Sprintf(
		"⚠️ *Error Alert*\n\n" +
			"*Message:* %s\n" +
			"*Timestamp:* %s",
		errorMessage,
		time.Now().Format("2006-01-02 15:04:05 MST"),
	)

	return t.sendMessage(message, "MarkdownV2")
}

// sendMessage sends a message to Telegram
func (t *TelegramNotifier) sendMessage(text, parseMode string) error {
	payload := map[string]interface{}{
		"chat_id":    t.chatID,
		"text":       text,
		"parse_mode": parseMode,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal telegram payload: %w", err)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.botToken)
	resp, err := t.client.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to send telegram message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned status code %d", resp.StatusCode)
	}

	return nil
}

// IsConfigured returns true if Telegram is properly configured
func (t *TelegramNotifier) IsConfigured() bool {
	return t.botToken != "" && t.chatID != ""
}
