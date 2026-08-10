package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	timeout        = 4 * time.Second
	serviceTimeout = 6 * time.Second
	maxConcurrency = 30 // Уменьшено до 30 для стабильного запуска ядер Xray/sing-box
	maxOutputLimit = 300

	StrictRuSNIOnly = true // Пропускать только российские SNI (.ru, .su, .рф)
	StrictVLESSOnly = true // Пропускать только VLESS (Reality/TLS)
	StrictPortsOnly = true // Пропускать только порты 443 и 80
)

type ConfigResult struct {
	URL            string
	Latency        time.Duration
	Score          int
	ServiceSuccess int // Количество успешно пройденных сервисов
}

type TargetService struct {
	Name string
	URL  string
}

// Список обязательных сервисов для полной проверки сквозной пропускной способности
var targetServices = []TargetService{
	{Name: "Google", URL: "https://www.google.com/generate_204"},
	{Name: "YouTube", URL: "https://www.youtube.com"},
	{Name: "Instagram", URL: "https://www.instagram.com"},
	{Name: "Telegram", URL: "https://t.me"},
	{Name: "WhatsApp", URL: "https://web.whatsapp.com"},
	{Name: "Viber", URL: "https://www.viber.com"},
	{Name: "GitHub", URL: "https://github.com"},
	{Name: "Gemini", URL: "https://gemini.google.com"},
	{Name: "ChatGPT", URL: "https://chatgpt.com"},
	{Name: "DeepSeek", URL: "https://chat.deepseek.com"},
}

// Заведомо заблокированные ТСПУ SNI / Домены
var blockedSNIs = []string{
	"instagram.com", "facebook.com", "twitter.com", "x.com",
	"ytimg.com", "ggpht.com", "googlevideo.com", "notion.so",
	"t.me", "telegram.org",
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
		src = strings.TrimSpace(src)
		if src == "" || strings.HasPrefix(src, "#") {
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

	fmt.Printf("Собрано %d уникальных конфигов. Запуск глубокого ТСПУ/Service валидатора...\n", len(uniqueConfigs))

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
		if res.Score > 0 {
			validResults = append(validResults, res)
		}
	}

	fmt.Printf("Успешно прошли полный комплекс проверок: %d конфигов.\n", len(validResults))

	sort.Slice(validResults, func(i, j int) bool {
		if validResults[i].ServiceSuccess == validResults[j].ServiceSuccess {
			return validResults[i].Score > validResults[j].Score
		}
		return validResults[i].ServiceSuccess > validResults[j].ServiceSuccess
	})

	if len(validResults) > maxOutputLimit {
		validResults = validResults[:maxOutputLimit]
	}

	var finalSlice []string
	for i, r := range validResults {
		// Присваиваем имена вида SNI 1, SNI 2, SNI 3...
		renamedURL := setConfigName(r.URL, fmt.Sprintf("SNI %d", i+1))
		finalSlice = append(finalSlice, renamedURL)
	}

	fmt.Printf("Сформирован ТОП-%d максимальной надежности.\n", len(finalSlice))

	rawOutput := strings.Join(finalSlice, "\n")
	os.WriteFile("output_raw.txt", []byte(rawOutput), 0644)

	b64Output := base64.StdEncoding.EncodeToString([]byte(rawOutput))
	os.WriteFile("output_base64.txt", []byte(b64Output), 0644)

	fmt.Println("Файлы output_raw.txt и output_base64.txt успешно обновлены.")
}

func fetchSubscription(targetURL string, out chan<- string) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	content := string(body)
	cleanContent := strings.TrimSpace(content)
	cleanContent = strings.ReplaceAll(cleanContent, "\r", "")
	cleanContent = strings.ReplaceAll(cleanContent, "\n", "")

	// Попытка декодировать Base64 (стандартным или URL безопасным кодеком)
	if decoded, err := base64.StdEncoding.DecodeString(cleanContent); err == nil {
		content = string(decoded)
	} else if decoded, err := base64.URLEncoding.DecodeString(cleanContent); err == nil {
		content = string(decoded)
	} else if decoded, err := base64.RawStdEncoding.DecodeString(cleanContent); err == nil {
		content = string(decoded)
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

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

	// 1. Фильтрация ТСПУ / Ru SNI
	if StrictPortsOnly && port != "443" && port != "80" {
		return ConfigResult{}, false
	}

	if StrictVLESSOnly && !strings.HasPrefix(lowerCfg, "vless://") {
		return ConfigResult{}, false
	}

	if isBlockedSNI(sni) {
		return ConfigResult{}, false
	}

	// Пропускать только конфигурации с Ru SNI (.ru, .su, .рф)
	if StrictRuSNIOnly && !isRuSNI(sni) {
		return ConfigResult{}, false
	}

	targetAddr := net.JoinHostPort(host, port)
	start := time.Now()

	// 2. Проверка базового подключения к прокси-ноде
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

	// 3. Проверка доступности целевых сервисов через НАСТОЯЩЕЕ ядро Xray / sing-box
	passedServices := checkTargetServicesViaProxy(configStr)

	// Если через реальное проксирование ни один сервис не ответил — отбрасываем
	if passedServices == 0 {
		return ConfigResult{}, false
	}

	score := calculateBypassScore(configStr, port, sni, transport, latency, passedServices)

	return ConfigResult{
		URL:            configStr,
		Latency:        latency,
		Score:          score,
		ServiceSuccess: passedServices,
	}, true
}

// ----------------------------------------------------------------------------------
//   НАСТОЯЩЕЕ ПРОКСИРОВАНИЕ ТРАФИКА ЧЕРЕЗ XRAY CORE
// ----------------------------------------------------------------------------------

func checkTargetServicesViaProxy(configStr string) int {
	socksPort, err := getFreePort()
	if err != nil {
		return 0
	}

	// Создаем временный конфигурационный файл для ядра Xray
	xrayConfigJSON, err := generateXrayConfig(configStr, socksPort)
	if err != nil {
		return 0
	}

	tmpFile, err := os.CreateTemp("", "xray_cfg_*.json")
	if err != nil {
		return 0
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(xrayConfigJSON); err != nil {
		tmpFile.Close()
		return 0
	}
	tmpFile.Close()

	// Находим бинарник xray в системе
	corePath := findCoreExecutable()
	if corePath == "" {
		// Если ядра нет, возвращаем 0, так как проверяем только реальный VLESS проход
		return 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), serviceTimeout+2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, corePath, "run", "-c", tmpFile.Name())

	if err := cmd.Start(); err != nil {
		return 0
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	// Ожидание готовности локального SOCKS5 порта вместо «слепого» sleep
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	ready := false
	for i := 0; i < 15; i++ {
		conn, err := net.DialTimeout("tcp", socksAddr, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(30 * time.Millisecond)
	}

	if !ready {
		return 0
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   serviceTimeout,
	}

	var wg sync.WaitGroup
	successChan := make(chan bool, len(targetServices))

	for _, service := range targetServices {
		wg.Add(1)
		go func(s TargetService) {
			defer wg.Done()

			req, err := http.NewRequestWithContext(ctx, "GET", s.URL, nil)
			if err != nil {
				successChan <- false
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

			resp, err := client.Do(req)
			if err != nil {
				successChan <- false
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				successChan <- true
			} else {
				successChan <- false
			}
		}(service)
	}

	wg.Wait()
	close(successChan)

	count := 0
	for ok := range successChan {
		if ok {
			count++
		}
	}

	return count
}

func generateXrayConfig(configURL string, socksPort int) ([]byte, error) {
	u, err := url.Parse(configURL)
	if err != nil {
		return nil, err
	}

	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		portStr = "443"
	}
	port, _ := strconv.Atoi(portStr)

	uuid := u.User.Username()
	query := u.Query()

	sni := query.Get("sni")
	if sni == "" {
		sni = query.Get("peer")
	}

	security := query.Get("security")
	if security == "" {
		security = "none"
	}

	netType := query.Get("type")
	if netType == "" {
		netType = "tcp"
	}

	pbk := query.Get("pbk")
	sid := query.Get("sid")
	fp := query.Get("fp")
	if fp == "" {
		fp = "chrome"
	}

	path := query.Get("path")
	flow := query.Get("flow")

	streamSettings := map[string]interface{}{
		"network":  netType,
		"security": security,
	}

	if security == "tls" {
		streamSettings["tlsSettings"] = map[string]interface{}{
			"serverName":    sni,
			"fingerprint":   fp,
			"allowInsecure": true,
		}
	} else if security == "reality" {
		streamSettings["realitySettings"] = map[string]interface{}{
			"serverName":  sni,
			"fingerprint": fp,
			"publicKey":   pbk,
			"shortId":     sid,
		}
	}

	if netType == "ws" {
		streamSettings["wsSettings"] = map[string]interface{}{
			"path": path,
		}
	} else if netType == "grpc" {
		streamSettings["grpcSettings"] = map[string]interface{}{
			"serviceName": query.Get("serviceName"),
		}
	}

	vnextUser := map[string]interface{}{
		"id":         uuid,
		"encryption": "none",
	}
	if flow != "" {
		vnextUser["flow"] = flow
	}

	config := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "none",
		},
		"inbounds": []map[string]interface{}{
			{
				"port":     socksPort,
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
				},
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"protocol": "vless",
				"settings": map[string]interface{}{
					"vnext": []map[string]interface{}{
						{
							"address": host,
							"port":    port,
							"users":   []map[string]interface{}{vnextUser},
						},
					},
				},
				"streamSettings": streamSettings,
			},
		},
	}

	return json.Marshal(config)
}

func getFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func findCoreExecutable() string {
	if path, err := exec.LookPath("xray"); err == nil {
		return path
	}
	if path, err := exec.LookPath("sing-box"); err == nil {
		return path
	}

	cwd, err := os.Getwd()
	if err == nil {
		xrayLocal := filepath.Join(cwd, "xray")
		if _, err := os.Stat(xrayLocal); err == nil {
			return xrayLocal
		}
		singLocal := filepath.Join(cwd, "sing-box")
		if _, err := os.Stat(singLocal); err == nil {
			return singLocal
		}
	}

	return ""
}

// ----------------------------------------------------------------------------------
//   ВСЕ ОСТАЛЬНЫЕ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (СОХРАНЕНЫ С ИСПРАВЛЕНИЯМИ)
// ----------------------------------------------------------------------------------

func checkTargetServices(configStr string) int {
	var wg sync.WaitGroup
	successChan := make(chan bool, len(targetServices))

	for _, service := range targetServices {
		wg.Add(1)
		go func(s TargetService) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), serviceTimeout)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, "GET", s.URL, nil)
			if err != nil {
				successChan <- false
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

			client := &http.Client{
				Timeout: serviceTimeout,
			}

			resp, err := client.Do(req)
			if err != nil {
				successChan <- false
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				successChan <- true
			} else {
				successChan <- false
			}
		}(service)
	}

	wg.Wait()
	close(successChan)

	count := 0
	for ok := range successChan {
		if ok {
			count++
		}
	}
	return count
}

func calculateBypassScore(configStr string, port string, sni string, transport string, latency time.Duration, passedServices int) int {
	score := 100 + (passedServices * 50)
	lower := strings.ToLower(configStr)

	if strings.Contains(lower, "security=reality") {
		score += 150
	}

	if transport == "grpc" {
		score += 50
	} else if transport == "ws" {
		score += 30
	}

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

func isRuSNI(sni string) bool {
	if sni == "" {
		return false
	}
	sniLower := strings.ToLower(strings.TrimSpace(sni))

	if strings.HasSuffix(sniLower, ".ru") || strings.HasSuffix(sniLower, ".su") || strings.HasSuffix(sniLower, ".xn--p1ai") || strings.HasSuffix(sniLower, ".рф") {
		return true
	}

	parts := strings.Split(sniLower, ".")
	if len(parts) > 1 {
		tld := parts[len(parts)-1]
		if tld == "ru" || tld == "su" || tld == "xn--p1ai" || tld == "рф" {
			return true
		}
	}

	return false
}

func setConfigName(configURL string, name string) string {
	escapedName := url.PathEscape(name)
	if idx := strings.Index(configURL, "#"); idx != -1 {
		return configURL[:idx] + "#" + escapedName
	}
	return configURL + "#" + escapedName
}

func parseConfigDetails(configStr string) (host string, port string, sni string, path string, transport string) {
	u, err := url.Parse(configStr)
	if err != nil {
		return "", "", "", "", ""
	}

	host = u.Hostname()
	port = u.Port()

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.Trim(host, "[]")
	}

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
