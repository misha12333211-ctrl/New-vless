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
	timeout        = 4 * time.Second
	maxConcurrency = 60
	maxOutputLimit = 300
)

type ConfigResult struct {
	URL     string
	Latency time.Duration
	Score   int
}

// Заведомо заблокированные ТСПУ SNI / Домены (Сразу отбрасываем)
var blockedSNIs = []string{
	"instagram.com", "facebook.com", "twitter.com", "x.com",
	"ytimg.com", "ggpht.com", "googlevideo.com", "notion.so",
	"t.me", "telegram.org",
}

// Доверенные CDN / Белые SNI для обхода строгой фильтрации
var trustedSNIs = []string{
	"cloudflare.com", "microsoft.com", "apple.com", "amazon.com",
	"yahoo.com", "zoom.us", "deb.debian.org", "cdn.jsdelivr.net",
	"yandex.ru", "vk.com", "sberbank.ru", "vk.me",
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

	fmt.Printf("Собрано %d уникальных конфигов. Начинаем глубокий HTTP/TLS/SNI тест...\n", len(uniqueConfigs))

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
		if res.Score > -1000 { // Отфильтровываем забракованные
			validResults = append(validResults, res)
		}
	}

	fmt.Printf("Прошли строгую валидацию: %d конфигов.\n", len(validResults))

	// Сортировка по итоговым очкам
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

	fmt.Printf("Сформирован ТОП-%d максимальной пробиваемости.\n", len(finalSlice))

	rawOutput := strings.Join(finalSlice, "\n")
	os.WriteFile("output_raw.txt", []byte(rawOutput), 0644)

	b64Output := base64.StdEncoding.EncodeToString([]byte(rawOutput))
	os.WriteFile("output_base64.txt", []byte(b64Output), 0644)

	fmt.Println("Файлы output_raw.txt и output_base64.txt успешно обновлены.")
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
	host, port, sni, path, transport := parseConfigDetails(configStr)
	if host == "" || port == "" {
		return ConfigResult{}, false
	}

	// Предварительная проверка SNI: выкидываем заблокированные домены
	if isBlockedSNI(sni) {
		return ConfigResult{}, false
	}

	targetAddr := net.JoinHostPort(host, port)
	start := time.Now()

	// 1. TCP Dial
	rawConn, err := net.DialTimeout("tcp", targetAddr, timeout)
	if err != nil {
		return ConfigResult{}, false
	}

	serverName := sni
	if serverName == "" {
		serverName = host
	}

	var conn net.Conn = rawConn
	isTLS := strings.Contains(configStr, "security=tls") || strings.Contains(configStr, "security=reality") || strings.HasPrefix(configStr, "trojan://")

	// 2. TLS / REALITY Handshake Test
	if isTLS {
		tlsConfig := &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
		}
		tlsConn := tls.Client(rawConn, tlsConfig)
		tlsConn.SetDeadline(time.Now().Add(timeout))

		if err := tlsConn.Handshake(); err != nil {
			_ = rawConn.Close()
			return ConfigResult{}, false
		}
		conn = tlsConn
	}

	// 3. HTTP Proxy / WebSocket Handshake Check (Реальный эхо-запрос)
	if transport == "ws" {
		wsReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", path, serverName)
		_ = conn.SetDeadline(time.Now().Add(timeout))
		_, err := conn.Write([]byte(wsReq))
		if err != nil {
			_ = conn.Close()
			return ConfigResult{}, false
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			_ = conn.Close()
			return ConfigResult{}, false
		}

		respStr := string(buf[:n])
		// Проверяем ответы "101 Switching Protocols" или "200 OK"
		if !strings.Contains(respStr, "101") && !strings.Contains(respStr, "200") && !strings.Contains(respStr, "HTTP/1.1") {
			_ = conn.Close()
			return ConfigResult{}, false
		}
	}

	latency := time.Since(start)
	_ = conn.Close()

	// 4. Оценка пробиваемости Белых Списков
	score := calculateBypassScore(configStr, port, sni, transport, latency)

	return ConfigResult{
		URL:     configStr,
		Latency: latency,
		Score:   score,
	}, true
}

func calculateBypassScore(configStr string, port string, sni string, transport string, latency time.Duration) int {
	score := 0
	lower := strings.ToLower(configStr)
	sniLower := strings.ToLower(sni)

	// 1. Фильтр Портов (Белые списки режут всё кроме 443/80)
	if port == "443" {
		score += 100 // Главный порт для маскировки
	} else if port == "80" || port == "8080" {
		score += 20
	} else {
		score -= 100 // Нестандартные порты жестко штрафуются
	}

	// 2. Оценка Протоколов и Транспорта
	if strings.HasPrefix(lower, "vless://") {
		score += 90
		if strings.Contains(lower, "security=reality") {
			score += 120 // REALITY — максимальная стойкость к ТСПУ
		} else if strings.Contains(lower, "security=tls") {
			score += 40
		}

		if transport == "grpc" {
			score += 50 // gRPC отлично проходит белые списки
		} else if transport == "ws" {
			score += 30
		}
	} else if strings.HasPrefix(lower, "hysteria2://") || strings.HasPrefix(lower, "hy2://") {
		score += 40 // UDP может полностью блокироваться при белых списках
	} else if strings.HasPrefix(lower, "trojan://") {
		score += 30
	} else {
		score -= 60 // Старые протоколы (VMess/SS) без маскировки отсеиваем
	}

	// 3. SNI Скоринг
	if sniLower != "" {
		for _, trusted := range trustedSNIs {
			if strings.Contains(sniLower, trusted) {
				score += 70 // Белый домен CDN/сервиса
				break
			}
		}
	} else if strings.Contains(lower, "security=reality") || strings.Contains(lower, "security=tls") {
		score -= 80 // TLS/Reality без SNI выйдет из строя
	}

	// 4. Штраф за задержку (пинг)
	pingMs := int(latency.Milliseconds())
	score -= pingMs / 5

	return score
}

func isBlockedSNI(sni string) bool {
	if sni == "" {
		return false
	}
	sniLower := strings.ToLower(sni)
	for _, blocked := range blockedSNIs {
		if strings.Contains(sniLower, blocked) {
			return true
		}
	}
	return false
}

func parseConfigDetails(configStr string) (host string, port string, sni string, path string, transport string) {
	u, err := url.Parse(configStr)
	if err != nil {
		return "", "", "", "", ""
	}

	host = u.Hostname()
	port = u.Port()

	query := u.Query()
	sni = query.Get("sni")
	if sni == "" {
		sni = query.Get("peer")
	}

	path = query.Get("path")
	if path == "" {
		path = "/"
	}

	transport = strings.ToLower(query.Get("type"))
	if transport == "" {
		transport = strings.ToLower(query.Get("headerType"))
	}

	if port == "" {
		switch u.Scheme {
		case "vless", "vmess", "trojan", "hysteria2", "hy2":
			port = "443"
		case "ss":
			port = "8388"
		}
	}

	return host, port, sni, path, transport
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
