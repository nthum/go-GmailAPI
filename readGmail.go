package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/mvdan/xurls"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	gmail "google.golang.org/api/gmail/v1"
)

func main() {
	ctx := context.Background()

	b, err := ioutil.ReadFile("client_secret.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	// If modifying these scopes, delete your previously saved credentials
	// at ~/.credentials/gmail-go-quickstart.json
	config, err := google.ConfigFromJSON(b, gmail.GmailReadonlyScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	client := getClient(ctx, config)

	srv, err := gmail.New(client)
	if err != nil {
		log.Fatalf("Unable to retrieve gmail Client %v", err)
	}

	user := "me"
	r, err := srv.Users.Messages.List(user).Q("malwarebytesta+test4@gmail.com").Do()
	// r, err := srv.Users.Messages.List(user).Q(userEmail).Do()
	if err != nil {
		log.Fatalf("Unable to retrieve message list. %v", err)
	}
	if len(r.Messages) > 0 {
		if len(r.Messages) == 1 {
			// fmt.Print("Message Id:\n")
			for _, l := range r.Messages {
				msg, err := srv.Users.Messages.Get(user, l.Id).Format("raw").Do()
				if err != nil {
					log.Fatalf("Unable to retrieve message. %v", err)
				}

				decoded, err := base64.URLEncoding.DecodeString(msg.Raw)
				if err != nil {
					fmt.Println("decode error:", err)
				}
				desiredURL := ""
				bodyUrls := xurls.Strict.FindAllString(string(decoded), -1)
				for _, nebulaURL := range bodyUrls {
					if strings.Contains(nebulaURL, "acceptinvite") {
						desiredURL = nebulaURL
					}

				}
				fmt.Printf("Invite Url:%v\n", desiredURL)
				parsedURL, err := url.Parse(desiredURL)
				if err != nil {
					fmt.Print("Cannot parse url")
				}
				tokenValue := parsedURL.Query().Get("token")
				// fmt.Println(tokenValue)

				if len(tokenValue) != 0 {
					// Accept_invite - Send Token
					// Uncomment later
					// acceptInviteReq := &bindings.AcceptInvite{
					// 	Token:       tokenValue,
					// 	DisplayName: fmt.Sprintf("Email Tester%s", model.NewID()),
					// 	Password:    "tapassword",
					// }
					// resp := test.AcceptUserInvite(t, acceptInviteReq, handler, tokenValue)
					// testapi.RequireStatusOK(t, testapi.New(t, resp))
				} else {
					fmt.Print("Token is empty")
				}
			}
		} else {
			fmt.Print("More than one message was found")
		}
	} else {
		fmt.Print("No Messages found.")
	}
}

func getClient(ctx context.Context, config *oauth2.Config) *http.Client {
	cacheFile, err := tokenCacheFile()
	if err != nil {
		log.Fatalf("Unable to get path to cached credential file. %v", err)
	}
	tok, err := tokenFromFile(cacheFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(cacheFile, tok)
	}
	return config.Client(ctx, tok)
}

func tokenCacheFile() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	tokenCacheDir := filepath.Join(usr.HomeDir, ".credentials")
	os.MkdirAll(tokenCacheDir, 0700)
	return filepath.Join(tokenCacheDir,
		url.QueryEscape("gmail-go-quickstart.json")), err
}

func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	t := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(t)
	defer f.Close()
	return t, err
}

func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var code string
	if _, err := fmt.Scan(&code); err != nil {
		log.Fatalf("Unable to read authorization code %v", err)
	}

	tok, err := config.Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web %v", err)
	}
	return tok
}

func saveToken(file string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", file)
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}
