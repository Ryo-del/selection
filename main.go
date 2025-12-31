package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"selection/bot"
	"strings"
	"sync"
	"time"
)

type BruteForceProtection struct {
	attempts map[string]int
	lock     sync.RWMutex
}
type Session struct {
	Nonce string
}

var store = make(map[string]Session)

var (
	lastUse  time.Time
	cooldown = 1 * time.Minute
	mu       sync.Mutex
)

func NewBruteForceProtection() *BruteForceProtection {
	bfp := &BruteForceProtection{
		attempts: make(map[string]int),
	}

	// Очистка старых записей каждые 5 минут
	go bfp.cleanupRoutine()

	return bfp
}
func WriteToFile(filename, data string) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(data + "\n"); err != nil {
		return err
	}
	return nil
}
func (b *BruteForceProtection) cleanupRoutine() {
	for {
		time.Sleep(5 * time.Minute)
		b.lock.Lock()
		b.attempts = make(map[string]int)
		b.lock.Unlock()
	}
}

func (b *BruteForceProtection) AddAttempt(ip string) {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.attempts[ip]++
}

func (b *BruteForceProtection) CheckBruteForce(ip string) bool {
	b.lock.RLock()
	defer b.lock.RUnlock()
	attempts, exists := b.attempts[ip]
	return exists && attempts >= 10 // Если 5+ попыток - считаем bruteforce
}

func (b *BruteForceProtection) IsBruteforceInput(input string) bool {
	input = strings.ToLower(strings.TrimSpace(input))

	// Проверка на слова связанные с bruteforce
	bruteWords := []string{
		"brute", "brud", "brote", "brut", "fors", "force",
		"брут", "форс", "бруд", "фос", "брот",
	}

	for _, word := range bruteWords {
		if strings.Contains(input, word) {
			return true
		}
	}

	// Конкретные варианты написания
	specificMatches := []string{
		"bruteforce", "brute force", "brute-force", "brutefors",
		"brudeforce", "brudefors", "brudfors", "брутфорс",
		"xd", // если вводят xd
	}

	for _, match := range specificMatches {
		if strings.Contains(input, match) {
			return true
		}
	}

	// Если слишком много цифр (типа brute123)
	digits := 0
	for _, c := range input {
		if c >= '0' && c <= '9' {
			digits++
		}
	}
	if digits > 3 && len(input) > 6 {
		return true
	}

	return false
}

var bfp = NewBruteForceProtection()

func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Credentials", "true")

			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}

		// Для preflight запроса
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func PlayGround(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		fmt.Fprintf(w, "hint: localhost:9999")
		ip := r.RemoteAddr
		bot.SendTG("Пользователь " + ip + " Нашёл подсказку")
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func CheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	password := r.FormValue("password")
	truePassword := "true password"

	// Получаем IP клиента
	ip := r.RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		ip = host
	}

	// Проверяем на bruteforce
	bfp.AddAttempt(ip)
	aboutUSER := string("Пользователь " + ip + " Ввёл " + password)
	// Если подозреваем bruteforce
	if bfp.CheckBruteForce(ip) || bfp.IsBruteforceInput(password) {
		mu.Lock()
		defer mu.Unlock()
		if time.Since(lastUse) >= cooldown {
			bot.SendTG(aboutUSER + " Пытался Забрудфорсить!")
			lastUse = time.Now()
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("BruteForce is the stupidest thing you can do."))
		fmt.Printf("[BRUTEFORCE DETECTED] IP: %s, Input: %s\n", ip, password)
		return
	} else {
		bot.SendTG(aboutUSER)
	}
	// Основная логика проверки пароля
	if password == truePassword {
		bot.SendTG("Пользователь " + ip + " Прошёл на 2 этап")
		w.WriteHeader(http.StatusAccepted) // 202
		w.Write([]byte("Password correct!"))
	} else if password == "OPEN" {
		bot.SendTG("Пользователь " + ip + " Нашёл фейк 1")
		w.WriteHeader(http.StatusOK) // 200
		w.Write([]byte("Your cognitive range is severely restricted — primitive in structure, insufficient for complex reasoning."))
	} else if password == "truth" {
		bot.SendTG("Пользователь " + ip + " Нашёл фейк 2")
		w.WriteHeader(http.StatusOK) // 200
		w.Write([]byte("This response represents marginal improvement, yet remains fundamentally unintelligent."))
	} else if password == "kncaffd" {
		bot.SendTG("Пользователь " + ip + " Нашёл фейк 3")
		w.WriteHeader(http.StatusOK) // 200
		w.Write([]byte("An intelligent agent would not confine its search to surface-level explanations."))
	} else if password != "" {
		w.WriteHeader(http.StatusOK) // 200
		w.Write([]byte("Received: " + password))
	} else {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No password provided"))
	}

	fmt.Printf("[REQUEST] IP: %s, Input: %s\n", ip, password)
}
func GenerateNonce(bytes int) (string, error) {
	b := make([]byte, bytes)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func GenerateSessionID() (string, error) {
	b := make([]byte, 32) // 256 бит
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GET /handshake — выдаём challenge
func HandshakeHandlerGet(w http.ResponseWriter, r *http.Request) {
	ip := r.RemoteAddr
	mu.Lock()
	defer mu.Unlock()
	if time.Since(lastUse) >= cooldown {
		bot.SendTG("Пользователь " + ip + " Прошёл на этап 3")
		lastUse = time.Now()
	}
	nonce, err := GenerateNonce(3) // 3 байта → 6 hex
	if err != nil {
		http.Error(w, "error generating nonce", http.StatusInternalServerError)
		return
	}

	sessionID, err := GenerateSessionID()
	if err != nil {
		http.Error(w, "error generating session id", http.StatusInternalServerError)
		return
	}

	// сохраняем состояние
	store[sessionID] = Session{Nonce: nonce}

	// отправляем cookie с session_id
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true, // 🔥 ВАЖНО
		Path:     "/",
	})

	// headers и JSON
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Checksum", "sha256")
	w.Header().Set("Cache-Control", "no-store")

	json.NewEncoder(w).Encode(map[string]string{
		"status": "incomplete",
		"nonce":  nonce,
	})
}

// POST /handshake — проверяем sha256(nonce)
func HandshakeHandlerPost(w http.ResponseWriter, r *http.Request) {
	// достаём cookie
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "no session cookie", http.StatusUnauthorized)
		return
	}
	sessionID := cookie.Value

	sess, ok := store[sessionID]
	if !ok {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}

	// читаем JSON
	var body struct {
		Input string `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if body.Input == "" {
		http.Error(w, "input required", http.StatusBadRequest)
		return
	}

	// сравниваем sha256
	expected := sha256.Sum256([]byte(sess.Nonce))
	if body.Input != hex.EncodeToString(expected[:]) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// одноразовый nonce
	delete(store, sessionID)

	// ответ клиенту
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "step_2",
		"next":   "/logic",
	})
}

// основной handler
func HandshakeHandler(w http.ResponseWriter, r *http.Request) {
	id := r.RemoteAddr
	bot.SendTG(id + "Прошел на 3 этап")
	switch r.Method {
	case http.MethodGet:
		HandshakeHandlerGet(w, r)
	case http.MethodPost:
		HandshakeHandlerPost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func main() {

	mux := http.NewServeMux()
	mux.Handle("/welldone/", http.StripPrefix("/welldone/", http.FileServer(http.Dir("welldone"))))
	mux.Handle("/Duck/", http.StripPrefix("/Duck/", http.FileServer(http.Dir("Duck"))))
	mux.HandleFunc("/handshake", HandshakeHandler)
	mux.HandleFunc("/start", CheckHandler)
	mux.HandleFunc("/", PlayGround)

	handler := CORS(mux)

	fmt.Println("Server starting on :8080")
	fmt.Println("Bruteforce protection enabled")
	if err := http.ListenAndServe(":8080", handler); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
