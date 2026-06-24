package main

import (
	"encoding/json"
	"log"
	"net/http"

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

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/health", healthHandler).Methods(http.MethodGet)
	r.HandleFunc("/hello", helloHandler).Methods(http.MethodGet)
	r.HandleFunc("/greet", greetHandler).Methods(http.MethodGet)

	log.Println("Server starting on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}
