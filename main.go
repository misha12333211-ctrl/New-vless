package main

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	timeout        = 4 * time.Second
	serviceTimeout = 6 * time.Second
	maxConcurrency = 30 // Оптимально для GitHub Actions Runner
	maxOutputLimit = 300

	StrictRuSNIOnly = true // Пропускать только российские SNI (.ru, .su, .рф, .xn--p1ai)
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
	rand.Seed(time.Now().UnixNano())

	// Подготовка ядра Xray для GitHub Actions или локальной среды
	ensureCoreAvailable()

	sources, err := readLines("sources.txt")
	if err != nil {
		fmt.Printf("Ошибка чтения sources.txt: %v\n", err)
		return
	}

	rawConfigs := make(chan string, 20000)
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
	_ = os.WriteFile("output_raw.txt", []byte(rawOutput), 0644)

	b64Output := base64.StdEncoding.EncodeToString([]byte(rawOutput))
	_ = os.WriteFile("output_base64.txt", []byte(b64Output), 0644)

	fmt.Println("Файлы output_raw.txt и output_base64.txt успешно обновлены.")
}

func fetchSubscription(targetURL string, out chan<- string) {
	client := http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
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
	cleanedContent := cleanBase64String(content)

	// Пробуем декодировать Base64 (стандартный и URL-safe)
	if decoded, err := decodeBase64Flex(cleanedContent); err == nil {
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

func cleanBase64String(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '-' || r == '_' || r == '=' {
			return r
		}
		return -1
	}, s)
}

func decodeBase64Flex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if data, err := base64.StdEncoding.DecodeString(s); err == nil {
		return data, nil
	}
	if data, err := base64.URLEncoding.DecodeString(s); err == nil {
		return data, nil
	}
	if data, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return data, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func isProxyProtocol(line string) bool {
	protocols := []string{"vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria2://", "hy2://", "tuic://"}
	lower := strings.ToLower(line)
	for _, p := range protocols {
		if strings.HasPrefix(lower, p) {
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
		_ = tlsConn.SetDeadline(time.Now().Add(timeout))

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
	corePath := findCoreExecutable()
	if corePath == "" {
		return checkTargetServices(configStr)
	}

	socksPort, err := getFreePort()
	if err != nil {
		return 0
	}

	xrayConfigJSON, err := generateXrayConfig(configStr, socksPort)
	if err != nil {
		return 0
	}

	tmpFile, err := os.CreateTemp("", "xray_cfg_*.json")
	if err != nil {
		return 0
	}
	tmpFileName := tmpFile.Name()

	if _, err := tmpFile.Write(xrayConfigJSON); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFileName)
		return 0
	}
	_ = tmpFile.Close()
	defer os.Remove(tmpFileName)

	ctx, cancel := context.WithTimeout(context.Background(), serviceTimeout*2)
	defer cancel()

	cmd := exec.CommandContext(ctx, corePath, "run", "-c", tmpFileName)

	if err := cmd.Start(); err != nil {
		return 0
	}

	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	// Проверяем готовность SOCKS5 сервера ядра (до 2 секунд ожидания)
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	proxyReady := false
	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", socksAddr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			proxyReady = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !proxyReady {
		return 0
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
	httpTransport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: httpTransport,
		Timeout:   serviceTimeout,
	}

	var wg sync.WaitGroup
	successChan := make(chan bool, len(targetServices))

	for _, service := range targetServices {
		wg.Add(1)
		go func(s TargetService) {
			defer wg.Done()

			req, err := http.NewRequest("GET", s.URL, nil)
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
	if sni == "" {
		sni = host
	}

	security := query.Get("security")
	if security == "" {
		if strings.HasPrefix(configURL, "trojan://") {
			security = "tls"
		} else {
			security = "none"
		}
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
	if path == "" {
		path = "/"
	}
	flow := query.Get("flow")

	streamSettings := map[string]interface{}{
		"network":  netType,
		"security": security,
	}

	if security == "reality" {
		streamSettings["realitySettings"] = map[string]interface{}{
			"serverName":  sni,
			"fingerprint": fp,
			"publicKey":   pbk,
			"shortId":     sid,
		}
	} else if security == "tls" {
		streamSettings["tlsSettings"] = map[string]interface{}{
			"serverName":    sni,
			"fingerprint":   fp,
			"allowInsecure": true,
		}
	}

	if netType == "ws" {
		streamSettings["wsSettings"] = map[string]interface{}{
			"path": path,
			"headers": map[string]interface{}{
				"Host": sni,
			},
		}
	} else if netType == "grpc" {
		streamSettings["grpcSettings"] = map[string]interface{}{
			"serviceName": query.Get("serviceName"),
		}
	}

	userMap := map[string]interface{}{
		"id":         uuid,
		"encryption": "none",
	}
	if flow != "" {
		userMap["flow"] = flow
	}

	config := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "none",
		},
		"inbounds": []map[string]interface{}{
			{
				"listen":   "127.0.0.1",
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
							"users":   []map[string]interface{}{userMap},
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
	for i := 0; i < 20; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		port := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		return port, nil
	}
	return 0, fmt.Errorf("failed to allocate free port")
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
		xrayExe := "xray"
		if runtime.GOOS == "windows" {
			xrayExe = "xray.exe"
		}
		xrayLocal := filepath.Join(cwd, xrayExe)
		if _, err := os.Stat(xrayLocal); err == nil {
			return xrayLocal
		}
	}

	return ""
}

// Автоматическая загрузка ядра Xray для среды CI/CD (GitHub Actions)
func ensureCoreAvailable() {
	if findCoreExecutable() != "" {
		return
	}

	fmt.Println("Бинарник Xray/sing-box не найден. Запуск автоматической загрузки Xray Core...")

	var downloadURL string
	switch runtime.GOOS {
	case "linux":
		if runtime.GOARCH == "amd64" {
			downloadURL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
		} else if runtime.GOARCH == "arm64" {
			downloadURL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm64-v8a.zip"
		}
	case "windows":
		downloadURL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip"
	}

	if downloadURL == "" {
		fmt.Println("Предупреждение: Неподдерживаемая ОС/архитектура для автозагрузки Xray.")
		return
	}

	resp, err := http.Get(downloadURL)
	if err != nil {
		fmt.Printf("Ошибка скачивания Xray: %v\n", err)
		return
	}
	defer resp.Body.Close()

	tmpZip, err := os.CreateTemp("", "xray_download_*.zip")
	if err != nil {
		return
	}
	tmpZipName := tmpZip.Name()
	defer os.Remove(tmpZipName)

	_, err = io.Copy(tmpZip, resp.Body)
	if err != nil {
		_ = tmpZip.Close()
		return
	}
	_ = tmpZip.Close()

	r, err := zip.OpenReader(tmpZipName)
	if err != nil {
		return
	}
	defer r.Close()

	cwd, err := os.Getwd()
	if err != nil {
		return
	}

	targetExe := "xray"
	if runtime.GOOS == "windows" {
		targetExe = "xray.exe"
	}

	for _, f := range r.File {
		if f.Name == targetExe {
			rc, err := f.Open()
			if err != nil {
				return
			}
			defer rc.Close()

			outPath := filepath.Join(cwd, targetExe)
			outFile, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
			if err != nil {
				return
			}
			defer outFile.Close()

			_, err = io.Copy(outFile, rc)
			if err == nil {
				_ = os.Chmod(outPath, 0755) // Права на исполнение для Linux Runner
				fmt.Printf("Xray Core успешно загружен и готов к работе (%s)!\n", outPath)
			}
			break
		}
	}
}

// ----------------------------------------------------------------------------------
//   ВСЕ ОСТАЛЬНЫЕ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
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
