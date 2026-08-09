package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	timeout        = 3 * time.Second
	maxConcurrency = 80
	maxOutputLimit = 300
)

type ConfigResult struct {
	URL     string
	Latency time.Duration
	Score   int
}

// Список доменов/SNI, которые заведомо заблокированы ТСПУ (снижают балл)
var blockedSNIs = []string{
	"instagram.com", "facebook.com", "twitter.com", "x.com",
	"ytimg.com", "ggpht.com", "googlevideo.com",
}

// Популярные CDN / белые SNI (повышают балл)
var trustedSNIs = []string{
	"cloudflare.com", "microsoft.com", "apple.com", "amazon.com",
	"yahoo.com", "zoom.us", "deb.debian.org", "cdn.jsdelivr.net",
}

func main() {
	sources, err := readLines("sources.txt")
	if err != nil {
		fmt.Printf("Ошибка чтения sources.txt: %v\n", err)
		return
	}

	rawConfigs := make(chan string, 10000)
	var wg sync.WaitGroup

	for _, src := range sources {
		if strings.TrimSpace(src) == "" || strings.HasPrefix(src, "#") {
			continue
		}
		wg.Add(1)
		go func(targetURL string) {
			defer wg.Done()
			fetchSubscription(targetURL, rawConfigs)
		}(src)
	}

	go func() {
		wg.Wait()
		close(rawConfigs)
	}()

	uniqueConfigs := make(map[string]bool)
	for cfg := range rawConfigs {
		cfg = strings.TrimSpace(cfg)
		if cfg != "" {
			uniqueConfigs[cfg] = true
		}
	}

	fmt.Printf("Собрано %d уникальных конфигов. Начинаем глубокое TLS/SNI тестирование...\n", len(uniqueConfigs))

	resultsChan := make(chan ConfigResult, len(uniqueConfigs))
	semaphore := make(chan struct{}, maxConcurrency)
	var testWg sync.WaitGroup

	for cfg := range uniqueConfigs {
		testWg.Add(1)
		go func(c string) {
			defer testWg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if res, ok := testConfig(c); ok {
				resultsChan <- res
			}
		}(cfg)
	}

	testWg.Wait()
	close(resultsChan)

	var validResults []ConfigResult
	for res := range resultsChan {
		validResults = append(validResults, res)
	}

	fmt.Printf("Прошли проверку (TCP + TLS Handshake): %d конфигов.\n", len(validResults))

	sort.Slice(validResults, func(i, j int) bool {
		return validResults[i].Score > validResults[j].Score
	})

	if len(validResults) > maxOutputLimit {
		validResults = validResults[:maxOutputLimit]
	}

	var finalSlice []string
	for _, r := range validResults {
		finalSlice = append(finalSlice, r.URL)
	}

	fmt.Printf("Отобрано ТОП-%d лучших конфигов.\n", len(finalSlice))

	rawOutput := strings.Join(finalSlice, "\n")
	os.WriteFile("output_raw.txt", []byte(rawOutput), 0644)

	b64Output := base64.StdEncoding.EncodeToString([]byte(rawOutput))
	os.WriteFile("output_base64.txt", []byte(b64Output), 0644)

	fmt.Println("Файлы output_raw.txt и output_base64.txt успешно сформированы.")
}

func fetchSubscription(targetURL string, out chan<- string) {
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	content := string(body)
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content)); err == nil {
		content = string(decoded)
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if isProxyProtocol(line) {
			out <- line
		}
	}
}

func isProxyProtocol(line string) bool {
	protocols := []string{"vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria2://", "hy2://", "tuic://"}
	for _, p := range protocols {
		if strings.HasPrefix(line, p) {
			return true
		}
	}
	return false
}

func testConfig(configStr string) (ConfigResult, bool) {
	host, port, sni := parseConfigDetails(configStr)
	if host == "" || port == "" {
		return ConfigResult{}, false
	}

	targetAddr := net.JoinHostPort(host, port)
	start := time.Now()

	// 1. Проверка базового TCP подключения
	rawConn, err := net.DialTimeout("tcp", targetAddr, timeout)
	if err != nil {
		return ConfigResult{}, false
	}

	// 2. Выполняем реальный TLS Handshake, если прокси использует TLS/Reality
	serverName := sni
	if serverName == "" {
		serverName = host
	}

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // Игнорируем самоподписанные/Reality сертификаты
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(timeout))

	// Пробуем провести хендшейк (работает для VLESS/Trojan/TLS)
	tlsErr := tlsConn.Handshake()
	latency := time.Since(start)

	// Закрываем соединения
	_ = tlsConn.Close()

	// Для TLS-протоколов падаем, если хендшейк не прошёл
	isTLSProtocol := strings.Contains(configStr, "security=tls") || strings.Contains(configStr, "security=reality") || strings.HasPrefix(configStr, "trojan://")
	if isTLSProtocol && tlsErr != nil {
		return ConfigResult{}, false
	}

	// 3. Оценка стойкости к ТСПУ и белым спискам
	score := calculateBypassScore(configStr, sni, latency)

	return ConfigResult{
		URL:     configStr,
		Latency: latency,
		Score:   score,
	}, true
}

func calculateBypassScore(configStr string, sni string, latency time.Duration) int {
	score := 0
	lower := strings.ToLower(configStr)
	sniLower := strings.ToLower(sni)

	// 1. Приоритет протоколов
	if strings.HasPrefix(lower, "vless://") {
		score += 80
		if strings.Contains(lower, "security=reality") {
			score += 60 // REALITY обходит ТСПУ/белые списки
		} else if strings.Contains(lower, "security=tls") {
			score += 20
		}
		if strings.Contains(lower, "type=grpc") {
			score += 25 // gRPC наименее подвержен фильтрации по длине пакетов
		} else if strings.Contains(lower, "type=ws") {
			score += 15
		}
	} else if strings.HasPrefix(lower, "hysteria2://") || strings.HasPrefix(lower, "hy2://") {
		score += 100 // UDP-маскировка, отлично преодолевает глушение
	} else if strings.HasPrefix(lower, "tuic://") {
		score += 90
	} else if strings.HasPrefix(lower, "trojan://") {
		score += 40
	} else {
		score += 10
	}

	// 2. Проверка SNI на заблокированные/белые домены
	if sniLower != "" {
		for _, blocked := range blockedSNIs {
			if strings.Contains(sniLower, blocked) {
				score -= 80 // SNI в блоклисте ТСПУ — высокий шанс бана
				break
			}
		}
		for _, trusted := range trustedSNIs {
			if strings.Contains(sniLower, trusted) {
				score += 30 // SNI из популярного CDN/сервиса
				break
			}
		}
	}

	// 3. Учитываем пинг
	pingMs := int(latency.Milliseconds())
	score -= pingMs / 10

	return score
}

func parseConfigDetails(configStr string) (host string, port string, sni string) {
	u, err := url.Parse(configStr)
	if err != nil {
		return "", "", ""
	}

	host = u.Hostname()
	port = u.Port()

	// Извлекаем SNI из query-параметров (?sni=... или ?peer=...)
	query := u.Query()
	sni = query.Get("sni")
	if sni == "" {
		sni = query.Get("peer")
	}

	if port == "" {
		switch u.Scheme {
		case "vless", "vmess", "trojan", "hysteria2", "hy2":
			port = "443"
		case "ss":
			port = "8388"
		}
	}

	return host, port, sni
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
