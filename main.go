package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"os"
	"text/tabwriter"
	
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/iris-contrib/middleware/cors"
	"crypto/rand"
	"github.com/kataras/iris/v12"
)

type Command struct {
	Command string `json:"command"`
}

type ShellResponse struct {
	Stdout string `json:"stdout"`
	Stderr  string `json:"stderr,omitempty"`
}

type PlatformResponse struct {
	GOOS string `json:"os"`
	GOARCH string `json:"arch"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

var signingKey []byte

func generateRandomSigningKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func generateToken(signingKey []byte) (string, error) {
	claims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Issuer:    "evanotebook-relay",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func verifyToken(tokenString string) (*jwt.Token, error) {
	parser := new(jwt.Parser)
	return parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
}

func checkOrigin(ctx iris.Context) {
	userIp := strings.Split(ctx.RemoteAddr(), ":")[0]
	if userIp != "127.0.0.1" && userIp != "::1" {
		ctx.StatusCode(http.StatusForbidden)
		return
	}
	ctx.Next()
}

func checkAuth(ctx iris.Context) {
	tokenString := ctx.GetHeader("Authorization")
	tokens := strings.Split(tokenString, "Bearer ")
	if len(tokens) != 2 {
		ctx.StatusCode(http.StatusUnauthorized)
		return
	}
	tokenString = tokens[1]
	if tokenString == "" {
		ctx.StatusCode(http.StatusUnauthorized)
		return
	}

	token, err := verifyToken(tokenString)
	if err != nil {
		ctx.StatusCode(http.StatusUnauthorized)
		return
	}

	if !token.Valid {
		ctx.StatusCode(http.StatusUnauthorized)
		return
	}

	ctx.Next()
}

func retrievePlatformInfo(ctx iris.Context) {
	response := PlatformResponse{
		GOOS: runtime.GOOS,
		GOARCH: runtime.GOARCH,
	}
	ctx.JSON(response)
}


func retrieveNewToken(ctx iris.Context) {
	tokenString, err := generateToken(signingKey)
	if err != nil {
		ctx.StatusCode(http.StatusBadRequest)
		ctx.WriteString(err.Error())
		return
	}
	response := TokenResponse{
		Token: tokenString,
	}
	ctx.JSON(response)
}

func execShell(ctx iris.Context) {
	var cmd Command
	if err := ctx.ReadJSON(&cmd); err != nil {
		ctx.StatusCode(http.StatusBadRequest)
		ctx.WriteString(err.Error())
		return
	}

	var stdout []byte
	var err error
	if runtime.GOOS == "windows" {
		stdout, err = exec.Command("powershell", "-Command", cmd.Command).Output()
	} else {
		stdout, err = exec.Command("/bin/sh", "-c", cmd.Command).Output()
	}

	response := ShellResponse{
		Stdout: string(bytes.TrimSpace(stdout)),
	}

	if err != nil {
		response.Stderr = err.Error()
	}

	ctx.JSON(response)
}

func updateTokenPeriodically() {
	for {
		tokenString, err := generateToken(signingKey)
		if err != nil {
			log.Println("Failed to generate token:", err)
		} else {
			fmt.Println("New JWT Token:", tokenString)
			time.Sleep(24 * time.Hour)
		}
	}
}

func writeDocs(url string) {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 2, '\t', 0)
	fmt.Fprintln(w, "URL\tMethod\tContent-Type\tbody\t")
	fmt.Fprintln(w, "http://"+url+"/v1/shell\tPOST\tJSON\t{command: string}\t")
	fmt.Fprintln(w, "http://"+url+"/v1/newToken\tGET\tJSON\t{token: string}\t")
	fmt.Fprintln(w, "http://"+url+"/v1/platformInfo\tGET\tJSON\t{arch: string; os: string;}\t")
	w.Flush()
}

func main() {
	app := iris.New()

	var err error
	signingKey, err = generateRandomSigningKey(10)
	if err != nil {
			log.Fatalf("Error generating signing key: %v", err)
			return
	}

	app.UseGlobal(checkOrigin)
	app.Use(checkAuth)

	app.UseRouter(cors.New(cors.Options{
		AllowedOrigins:   []string{
			"https://notebook.sanchezcarlosjr.com",
			"https://n.sanchezcarlosjr.com",
			"https://ipfsnotebook.sanchezcarlosjr.com",
			"http://localhost:4200",
			"https://webcontainer.web.app",
		},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}))

	v1 := app.Party("/v1")
    {
        v1.Post("/shell", execShell)
		v1.Get("/newToken", retrieveNewToken)
		v1.Get("/platformInfo", retrievePlatformInfo)
    }

	url := "localhost:8382"

	writeDocs(url)

	go updateTokenPeriodically()

	app.Run(iris.Addr(url))
}
