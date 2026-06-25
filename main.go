package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

type Response struct {
	Message string `json:"message"`
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{Message: "ok"})
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{Message: "Hello, World!"})
}

// greetHandler uses golang.org/x/text to format a localized greeting.
// golang.org/x/text v0.3.3 is vulnerable to CVE-2021-38561 (GO-2021-0113):
// out-of-bounds read in language tag parsing via a crafted BCP 47 tag.
func greetHandler(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	if lang == "" {
		lang = "en"
	}

	tag, err := language.Parse(lang)
	if err != nil {
		http.Error(w, "invalid language tag", http.StatusBadRequest)
		return
	}

	p := message.NewPrinter(tag)
	greeting := p.Sprintf("Hello from locale: %s", tag)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{Message: greeting})
}

var jwtSecret = []byte("supersecret")

// tokenHandler issues a JWT using github.com/dgrijalva/jwt-go v3.2.0.
// That version is vulnerable to CVE-2020-26160: the library does not properly
// validate the `aud` claim when it is a string instead of a []string, so an
// attacker can craft a token accepted by an unintended audience.
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	claims := jwt.MapClaims{
		"sub": "user123",
		"aud": "myservice",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "could not sign token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": signed})
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("token")
	token, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{Message: "token valid"})
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/health", healthHandler).Methods(http.MethodGet)
	r.HandleFunc("/hello", helloHandler).Methods(http.MethodGet)
	r.HandleFunc("/greet", greetHandler).Methods(http.MethodGet)
	r.HandleFunc("/token", tokenHandler).Methods(http.MethodGet)
	r.HandleFunc("/verify", verifyHandler).Methods(http.MethodGet)

	log.Println("Server starting on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}
