package main

import (
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"syscall"

	"github.com/andygrunwald/go-jira"
	"github.com/nlopes/slack"
)

var (
	yourProgram = regexp.MustCompile(`(?i)I('|’|)m your program(\?|)$`)

	sayYes = []*regexp.Regexp{
		yourProgram,
		regexp.MustCompile(`(?i)Hey(\!|) Hold it right there(\!|)$`),
		regexp.MustCompile(`(?i)What do you mean(,|) (\"|)yes(\"|)\?$`),
		regexp.MustCompile(`(?i)Know anything else\?$`),
		regexp.MustCompile(`(?i)Positive and negative, huh\? You('|’|)re a Bit(\.|)$`),
		regexp.MustCompile(`(?i)Are you a bit\?$`),
		regexp.MustCompile(`(?i)You don('|’|)t know much(\!|\.|)$`),
		regexp.MustCompile(`(?i)You should have a ping handler(\!|\.|)$`),
	}
	sayNo = []*regexp.Regexp{
		regexp.MustCompile(`(?i)Is that all you can say\?$`),
		regexp.MustCompile(`(?i)Pretty good driving(,|) huh\?$`),
		regexp.MustCompile(`(?i)Well(\,|) where('|’|)s your program\? Isn('|’|)t he going to miss you\?`),
		regexp.MustCompile(`(?i)Are you a bot\?$`),
		regexp.MustCompile(`(?i)You must be a bot(\!|\.|)$`),
	}
	sayYesYes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)Another mouth to feed(\.|)$`),
		regexp.MustCompile(`(?i)Do we have to pay you\?$`),
	}
	sayBlank = []*regexp.Regexp{
		regexp.MustCompile(`(?i)Say hello to`),
		regexp.MustCompile(`(?i)Hey(\!|)$`),
		regexp.MustCompile(`(?i)Hello(\!|\.|\?|)`),
	}

	jiraMatch = regexp.MustCompile(`(?i)(SMARTCOIN|DP|DEVOPS)\-{0-9}+`)

	myPrograms = []string{
		"U1KTQFXBR", // louis
		"U1L821JAY", // hiro
		"U1KT4UQ57", // dennis
	}
)

const (
	YESDOT       = "Yes."
	YESDOTImg    = "https://s3-ap-northeast-1.amazonaws.com/orb-bit/BitYes.jpg"
	NODOT        = "No."
	NODOTImg     = "https://s3-ap-northeast-1.amazonaws.com/orb-bit/BitNo.jpg"
	YESYESDOT    = "Yesyesyesyesyes!"
	YESYESDOTImg = "https://s3-ap-northeast-1.amazonaws.com/orb-bit/BitYesYesYesYes.png"
	BLANKDOT     = " "
	BLANKDOTImg  = "https://avatars.slack-edge.com/2016-07-21/61907309799_6d32a707899dabc11c80_48.png"

//	BLANKDOTImg = "https://s3-ap-northeast-1.amazonaws.com/orb-bit/BitNull.jpg"
)

func isMyProgram(u string) bool {
	for _, user := range myPrograms {
		if user == u {
			return true
		}
	}
	return false
}

func addUser(u string) {
	myPrograms = append(myPrograms, u)
}

type checkSend func(string) bool

type sendItems struct {
	img, msg string
	chk      checkSend
}

func sendYes(m string) bool {
	for _, r := range sayYes {
		if r.MatchString(m) {
			return true
		}
	}
	return false
}

func sendNo(m string) bool {
	for _, r := range sayNo {
		if r.MatchString(m) {
			return true
		}
	}
	return false
}

func sendYesYes(m string) bool {
	for _, r := range sayYesYes {
		if r.MatchString(m) {
			return true
		}
	}
	return false
}

func sendBlank(m string) bool {
	for _, r := range sayBlank {
		if r.MatchString(m) {
			return true
		}
	}
	return false
}

var checks = []*sendItems{
	&sendItems{YESDOTImg, YESDOT, sendYes},
	&sendItems{NODOTImg, NODOT, sendNo},
	&sendItems{YESYESDOTImg, YESYESDOT, sendYesYes},
	&sendItems{BLANKDOTImg, BLANKDOT, sendBlank},
}

func handleMsg(rtm *slack.RTM, chl, msg string) {
	for _, send := range checks {
		if send.chk(msg) {
			params := slack.PostMessageParameters{
				IconURL:  send.img,
				Username: "bit",
			}

			_, _, err := rtm.PostMessage(chl, send.msg, params)
			if err != nil {
				fmt.Println("post message err:", err)
			}
			break
		}
	}
}

func getIssue(name string) {

	jiraClient, err := jira.NewClient(nil, "https://coinpass.atlassian.net/")
	if err != nil {
		panic(err)
	}

	res, err := jiraClient.Authentication.AcquireSessionCookie(os.Getenv("JIRA_USER"), os.Getenv("JIRA_PASS"))
	if err != nil || res == false {
		fmt.Printf("Result: %v\n", res)
		panic(err)
	}

	issue, _, err := jiraClient.Issue.Get(name)
	if err != nil {
		panic(err)
	}

	fmt.Println("ISSUE:", issue, "\n", issue.Fields.Description)
	// title: issue.Fields.Summary
	// description: issue.Fields.Description
	// status: issue.Fields.Status.Name
	// type: issue.Fields.Type.Name

}

func main() {
	getIssue("SMARTCOIN-1126")
	return

	key := os.Getenv("SLACK_API_KEY")
	myName := os.Getenv("SLACK_BOT_NAME")

	api := slack.New(key)

	users, err := api.GetUsers()
	if err != nil {
		fmt.Println("get users err:", err)
		return
	}

	var me slack.User
	for _, user := range users {
		if user.Name != myName {
			continue
		}
		me = user
		break
	}

	rtm := api.NewRTM()
	go rtm.ManageConnection()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	listen := true

	findMe := regexp.MustCompile(fmt.Sprintf(`<@%s>`, me.ID))

	for listen {
		select {
		case incoming, ok := <-rtm.IncomingEvents:
			if !ok {
				listen = false
				break
			}
			fmt.Println("incoming:", incoming)

			// handle events
			switch ev := incoming.Data.(type) {
			case *slack.MessageEvent:
				if !findMe.MatchString(ev.Msg.Text) {
					break
				} else if !isMyProgram(ev.Msg.User) {
					if !yourProgram.MatchString(ev.Msg.Text) {
						break
					}
					addUser(ev.Msg.User)

					params := slack.PostMessageParameters{
						Username: "bit",
						IconURL:  YESDOTImg,
					}

					_, _, err = rtm.PostMessage(ev.Msg.Channel, YESDOT, params)
					if err != nil {
						fmt.Println("post message err:", err)
					}
				} else {
					handleMsg(rtm, ev.Msg.Channel, ev.Msg.Text)
				}
			}
		case <-shutdown:
			listen = false
		}
	}

	rtm.Disconnect()
}
