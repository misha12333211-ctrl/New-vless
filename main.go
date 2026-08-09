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

	// ЖЕСТКИЕ НАСТРОЙКИ СТРОГОГО РЕЖИМА БЕЛЫХ СПИСКОВ / ТСПУ
	StrictWhitelistMode = true // Отбрасывать всё, у чего SNI не входит в trustedSNIs
	StrictVLESSOnly     = true // Пропускать ТОЛЬКО VLESS (Reality/TLS)
	StrictPortsOnly     = true // Пропускать ТОЛЬКО порты 443 и 80
)

type ConfigResult struct {
	URL     string
	Latency time.Duration
	Score   int
}

// Заведомо заблокированные ТСПУ SNI / Домены (Мгновенный отказ)
var blockedSNIs = []string{
	"instagram.com", "facebook.com", "twitter.com", "x.com",
	"ytimg.com", "ggpht.com", "googlevideo.com", "notion.so",
	"t.me", "telegram.org",
}

// Белый список SNI (Рунет + крупные проверенные CDN)
var trustedSNIs = []string{
	// Яндекс
	"ya.ru", "yandex.ru", "yandex.com", "api-maps.yandex.ru", "avatars.mds.yandex.net",
	"browser.yandex.ru", "dzen.ru", "kinopoisk.ru", "hd.kinopoisk.ru", "st.kinopoisk.ru",
	"mail.yandex.ru", "mc.yandex.ru", "strm.yandex.ru", "travel.yandex.ru", "uslugi.yandex.ru",
	// VK & Mail.ru
	"vk.com", "vk.ru", "m.vk.com", "api.vk.ru", "id.vk.ru", "login.vk.com",
	"music.vk.ru", "cloud.vk.ru", "ads.vk.ru", "business.vk.ru", "target.vk.ru",
	"userapi.com", "vk-portal.net", "mail.ru", "e.mail.ru", "go.mail.ru", "cloud.mail.ru",
	"my.mail.ru", "news.mail.ru", "auto.mail.ru", "hi-tech.mail.ru", "otvet.mail.ru", "imgsmail.ru",
	// Маркетплейсы
	"avito.ru", "m.avito.ru", "avito.st", "ozon.ru", "www.ozon.ru", "bank.ozon.ru",
	"seller.ozon.ru", "st.ozone.ru", "wb.ru", "a.wb.ru", "finance.wb.ru", "wildberries.ru", "lemanapro.ru",
	// Банки
	"sberbank.ru", "online.sberbank.ru", "id.sber.ru", "tbank.ru", "id.tbank.ru",
	"cdn.tbank.ru", "alfabank.ru", "alfa-mobile.alfabank.ru", "vtb.ru", "www.vtb.ru", "pochtabank.mail.ru",
	// Гос. сервисы
	"gosuslugi.ru", "esia.gosuslugi.ru", "lk.gosuslugi.ru", "pos.gosuslugi.ru", "nalog.gov.ru", "sfr.gov.ru",
	"digital.gov.ru", "duma.gov.ru", "kremlin.ru", "roskachestvo.gov.ru", "pochta.ru", "izbirkom.ru", "mos.ru",
	// Карты, навигация, транспорт
	"2gis.ru", "2gis.com", "api.2gis.ru", "catalog.api.2gis.com", "tile0.maps.2gis.com",
	"rzd.ru", "www.rzd.ru", "ticket.rzd.ru", "cargo.rzd.ru", "travel.rzd.ru", "tutu.ru",
	// Мессенджеры и медиа
	"ok.ru", "m.ok.ru", "api.ok.ru", "st.okcdn.ru", "tamtam.ok.ru",
	"rutube.ru", "static.rutube.ru", "rambler.ru", "lenta.ru", "rbc.ru", "kp.ru", "gazeta.ru",
	// Операторы связи
	"beeline.ru", "mts.ru", "megafon.ru", "tele2.ru", "yota.ru", "rt.ru", "rostelecom.ru",
	// Международные инфраструктурные CDN
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

	fmt.Printf("Собрано %d уникальных конфигов. Начинаем жесткую фильтрацию под Белые Списки...\n", len(uniqueConfigs))

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
		if res.Score > 0 { // Пропускаем только конфиги с положительным счетом
			validResults = append(validResults, res)
		}
	}

	fmt.Printf("Успешно прошли проверку Белых Списков: %d конфигов.\n", len(validResults))

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

	lowerCfg := strings.ToLower(configStr)

	// --- 1. ЖЕСТКАЯ ФИЛЬТРАЦИЯ (HARD DROP) ДО СЕТЕВЫХ ТЕСТОВ ---

	// Проверка портов
	if StrictPortsOnly && port != "443" && port != "80" {
		return ConfigResult{}, false
	}

	// Проверка протокола
	if StrictVLESSOnly && !strings.HasPrefix(lowerCfg, "vless://") {
		return ConfigResult{}, false
	}

	// Проверка заблокированных SNI
	if isBlockedSNI(sni) {
		return ConfigResult{}, false
	}

	// Проверка Белого Списка (Whitelist Check)
	if StrictWhitelistMode && !isTrustedSNI(sni) {
		return ConfigResult{}, false
	}

	targetAddr := net.JoinHostPort(host, port)
	start := time.Now()

	// --- 2. TCP DIAL TEST ---
	rawConn, err := net.DialTimeout("tcp", targetAddr, timeout)
	if err != nil {
		return ConfigResult{}, false
	}

	serverName := sni
	if serverName == "" {
		serverName = host
	}

	var conn net.Conn = rawConn
	isTLS := strings.Contains(lowerCfg, "security=tls") || strings.Contains(lowerCfg, "security=reality") || strings.HasPrefix(lowerCfg, "trojan://")

	// --- 3. REALITY / TLS HANDSHAKE TEST ---
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

	// --- 4. HTTP PROXY / WEBSOCKET HANDSHAKE TEST ---
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
		if !strings.Contains(respStr, "101") && !strings.Contains(respStr, "200") && !strings.Contains(respStr, "HTTP/1.1") {
			_ = conn.Close()
			return ConfigResult{}, false
		}
	}

	latency := time.Since(start)
	_ = conn.Close()

	// --- 5. ФИНАЛЬНЫЙ СКОРИНГ (Только для оставшихся выживших) ---
	score := calculateBypassScore(configStr, port, sni, transport, latency)

	return ConfigResult{
		URL:     configStr,
		Latency: latency,
		Score:   score,
	}, true
}

func calculateBypassScore(configStr string, port string, sni string, transport string, latency time.Duration) int {
	score := 100 // Базовый балл для прошедшего фильтры конфига
	lower := strings.ToLower(configStr)

	// Бонус за REALITY
	if strings.Contains(lower, "security=reality") {
		score += 100
	}

	// Бонус за надежный транспорт
	if transport == "grpc" {
		score += 50
	} else if transport == "ws" {
		score += 30
	}

	// Штраф за пинг
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

func isTrustedSNI(sni string) bool {
	if sni == "" {
		return false
	}
	sniLower := strings.ToLower(sni)
	for _, trusted := range trustedSNIs {
		if strings.Contains(sniLower, trusted) {
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
