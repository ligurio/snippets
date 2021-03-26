package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
)

const (
	botToken string = ""
	chatID   int64  = 0

	msgHubOnline  = "Ïîòåðÿíà ñâÿçü ñ äîìîì"
	msgHubOffline = "Âîññòàíîâëåíà ñâÿçü ñ äîìîì"
)

var (
	commands      = make(chan string, 20)
	lastQueryTime time.Time
)

func runBot(bot *tgbotapi.BotAPI) {
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates, err := bot.GetUpdatesChan(u)
	if err != nil {
		log.Fatal(err)
	}
	for update := range updates {
		if update.Message == nil || update.Message.Chat.ID != chatID || len(update.Message.Command()) == 0 {
			continue
		}
		if cap(commands) == len(commands) {
			<-commands
		}
		commands <- strings.ToLower(update.Message.Command())
		//log.Printf("[%s] %s", update.Message.From.UserName, update.Message.Text)
	}
}

func checkHub(bot *tgbotapi.BotAPI) {
	hubOnline := true
	for {
		time.Sleep(60 * time.Second)
		minutes := time.Since(lastQueryTime).Minutes()
		if hubOnline && minutes > 1 {
			hubOnline = false
			bot.Send(tgbotapi.NewMessage(chatID, msgHubOffline))
		} else if !hubOnline && minutes < 1 {
			hubOnline = true
			bot.Send(tgbotapi.NewMessage(chatID, msgHubOnline))
		}
	}
}

func sendCommand(w http.ResponseWriter, req *http.Request) {
	lastQueryTime = time.Now()
	if len(commands) > 0 {
		fmt.Fprint(w, <-commands)
	} else {
		fmt.Fprint(w, "none")
	}
}

func main() {
	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Fatal(err)
	}
	go runBot(bot)
	go checkHub(bot)
	http.HandleFunc("/getcmd", sendCommand)
	http.ListenAndServe(":81", nil)
}