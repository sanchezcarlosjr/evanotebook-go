package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"runtime"
	"fmt"
	"log"
	"net/http"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"crypto/rand"
)

type Command struct {
	Command string `json:"command"`
}

type Response struct {
	Stdout string `json:"stdout"`
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

func checkOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "127.0.0.1" || r.RemoteAddr != "::1" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "https://notebook.sanchezcarlosjr.com" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func checkAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	
		token, err := verifyToken(tokenString)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	
		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func handler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var cmd Command
	err := decoder.Decode(&cmd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var stdout []byte
	if runtime.GOOS == "windows" {
		stdout, err = exec.Command("powershell", "-Command", cmd.Command).Output()
	} else {
		stdout, err = exec.Command("/bin/sh", "-c", cmd.Command).Output()
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := Response{
		Stdout: string(bytes.TrimSpace(stdout)),
	}

	encoder := json.NewEncoder(w)
	err = encoder.Encode(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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

func main() {
	signingKey, _ = generateRandomSigningKey(10)

	go updateTokenPeriodically()

	handler := http.HandlerFunc(handler)
	http.Handle("/", checkAuth(checkOrigin(handler)))
	http.ListenAndServe("localhost:8382", nil)
}