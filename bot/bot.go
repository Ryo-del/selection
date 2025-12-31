package bot

import (
	"log"
	"os"
	"strconv"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/joho/godotenv"
)

var bot *tgbotapi.BotAPI
var chatID int64

func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️ .env not loaded (using system env)")
	}

	token := os.Getenv("TG")
	if token == "" {
		log.Panic("TG token is not set")
	}

	var err error
	bot, err = tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Panic(err)
	}

	chatIDStr := os.Getenv("CHAT_ID")
	if chatIDStr == "" {
		log.Panic("TG_CHAT_ID is not set")
	}

	chatID, err = strconv.ParseInt(chatIDStr, 10, 64)
	if err != nil {
		log.Panic("Invalid TG_CHAT_ID")
	}

	log.Printf("Telegram bot initialized: @%s", bot.Self.UserName)
}
func SendTG(text string) {
	msg := tgbotapi.NewMessage(chatID, text)

	if _, err := bot.Send(msg); err != nil {
		log.Println("TG send error:", err)
	}
}
