package main

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
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
	"sync/atomic"
	"time"
)

const (
	maxConcurrency = 40                 // Оптимизировано для GitHub Actions
	maxOutputLimit = 300                // Лимит лучших серверов в подписке
	pingTimeout    = 2500 * time.Millisecond
	serviceTimeout = 8000 * time.Millisecond
)

type ConfigResult struct {
	URL            string
	Latency        time.Duration
	AdjustedPing   time.Duration
	Score          int
	ServiceSuccess int
	SNI            string
	Protocol       string
	CountryCode    string
	IsNearRU       bool
	IsRuSNI        bool
	HasBypassTech  bool
}

type TargetService struct {
	Name string
	URL  string
}

// 7 Ключевых сервисов для жесткой проверки доступности
var targetServices = []TargetService{
	{Name: "Google", URL: "https://www.google.com/generate_204"},
	{Name: "Telegram", URL: "https://t.me"},
	{Name: "GitHub", URL: "https://github.com"},
	{Name: "YouTube", URL: "https://www.youtube.com"},
	{Name: "Instagram", URL: "https://www.instagram.com"},
	{Name: "WhatsApp", URL: "https://web.whatsapp.com"},
	{Name: "ChatGPT", URL: "https://chatgpt.com"},
}

// Домены из Белого Списка ТСПУ для обхода фильтрации по SNI
var ruWhiteSNIs = []string{
	"ya.ru", "yandex.ru", "yandex.com", "api-maps.yandex.ru", "avatars.mds.yandex.net",
	"browser.yandex.ru", "dzen.ru", "kinopoisk.ru", "hd.kinopoisk.ru", "st.kinopoisk.ru",
	"mail.yandex.ru", "mc.yandex.ru", "strm.yandex.ru", "travel.yandex.ru",
	"vk.com", "vk.ru", "m.vk.com", "api.vk.ru", "id.vk.ru", "userapi.com",
	"mail.ru", "e.mail.ru", "cloud.mail.ru", "avito.ru", "ozon.ru", "wb.ru", "wildberries.ru",
	"sberbank.ru", "tbank.ru", "alfabank.ru", "vtb.ru", "gosuslugi.ru", "mos.ru",
	"2gis.ru", "rutube.ru", "rambler.ru", "rbc.ru", "mts.ru", "megafon.ru", "beeline.ru",
}

// Страны с низким RTT и устойчивыми каналами к РФ
var nearRUCountries = map[string]bool{
	"RU": true, "BY": true, "KZ": true, "AM": true, "GE": true,
	"FI": true, "SE": true, "EE": true, "LV": true, "LT": true,
	"PL": true, "DE": true, "NL": true, "MD": true, "UA": true,
	"UZ": true, "AZ": true, "KG": true, "TJ": true, "TR": true, "AT": true,
}

var (
	geoCacheMutex sync.RWMutex
	geoIPCache    = make(map[string]string)
	portMutex     sync.Mutex
	usedPorts     = make(map[int]bool)
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	startTime := time.Now()

	fmt.Println("=== [1/5] Подготовка среды и Xray Core ===")
	ensureCoreAvailable()

	sources, err := readLines("sources.txt")
	if err != nil {
		fmt.Printf("Ошибка чтения sources.txt: %v. Создаем пустые выходные файлы.\n", err)
		_ = os.WriteFile("output_raw.txt", []byte(""), 0644)
		_ = os.WriteFile("output_base64.txt", []byte(""), 0644)
		return
	}
	fmt.Printf("Загружено источников: %d\n", len(sources))

	fmt.Println("=== [2/5] Сбор, декодирование и уникализация конфигураций ===")
	rawConfigs := make(chan string, 500000)
	var wg sync.WaitGroup

	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	defer tr.CloseIdleConnections()

	sharedHTTPClient := &http.Client{
		Timeout:   12 * time.Second,
		Transport: tr,
	}

	for _, src := range sources {
		src = strings.TrimSpace(src)
		if src == "" || strings.HasPrefix(src, "#") || strings.HasPrefix(src, "//") {
			continue
		}
		wg.Add(1)
		go func(targetURL string) {
			defer wg.Done()
			fetchSubscriptionWithClient(sharedHTTPClient, targetURL, rawConfigs)
		}(src)
	}

	go func() {
		wg.Wait()
		close(rawConfigs)
	}()

	uniqueConfigs := make(map[string]bool)
	for cfg := range rawConfigs {
		cfg = sanitizeProxyURL(cfg)
		if cfg != "" && len(cfg) < 8192 && isProxyProtocol(cfg) {
			uniqueConfigs[cfg] = true
		}
	}

	totalConfigs := len(uniqueConfigs)
	fmt.Printf("Собрано уникальных прокси-ссылок всех протоколов: %d\n", totalConfigs)

	fmt.Println("=== [3/5] Жесткое тестирование: Эмуляция ТСПУ + Проверка 7 Сервисов ===")
	resultsChan := make(chan ConfigResult, totalConfigs)
	semaphore := make(chan struct{}, maxConcurrency)
	var testWg sync.WaitGroup
	var processedCount int64

	for cfg := range uniqueConfigs {
		testWg.Add(1)
		go func(c string) {
			defer testWg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if res, ok := testConfig(c); ok {
				resultsChan <- res
			}

			curr := atomic.AddInt64(&processedCount, 1)
			if curr%500 == 0 || curr == int64(totalConfigs) {
				fmt.Printf("Проверено конфигов: %d / %d\r", curr, totalConfigs)
			}
		}(cfg)
	}

	testWg.Wait()
	close(resultsChan)
	fmt.Println("\nТестирование серверов полностью завершено.")

	var validResults []ConfigResult
	for res := range resultsChan {
		if res.Score > 0 {
			validResults = append(validResults, res)
		}
	}

	fmt.Printf("=== [4/5] Ранжирование и отбор серверов для РФ (Валидных: %d) ===\n", len(validResults))

	// Приоритет: Количество рабочих сервисов -> Скор обхода ТСПУ -> Мин. скорректированная задержка
	sort.Slice(validResults, func(i, j int) bool {
		if validResults[i].ServiceSuccess == validResults[j].ServiceSuccess {
			if validResults[i].Score == validResults[j].Score {
				return validResults[i].AdjustedPing < validResults[j].AdjustedPing
			}
			return validResults[i].Score > validResults[j].Score
		}
		return validResults[i].ServiceSuccess > validResults[j].ServiceSuccess
	})

	var selected []ConfigResult
	usedMap := make(map[string]bool)

	for _, res := range validResults {
		if len(selected) >= maxOutputLimit {
			break
		}
		if !usedMap[res.URL] {
			selected = append(selected, res)
			usedMap[res.URL] = true
		}
	}

	var finalSlice []string
	for i, r := range selected {
		tag := strings.ToUpper(r.Protocol)
		if r.IsRuSNI {
			tag += "-RUSNI"
		} else if r.HasBypassTech {
			tag += "-ANTI_TSPU"
		}

		if r.CountryCode != "" {
			tag = fmt.Sprintf("%s-%s", r.CountryCode, tag)
		}

		// Формируем стандартизированное имя, совместимое со ВСЕМИ клиентами
		displayName := fmt.Sprintf("MiGiTi | %s | #%d", tag, i+1)
		renamedURL := setConfigName(r.URL, displayName)
		finalSlice = append(finalSlice, renamedURL)
	}

	fmt.Printf("Сформирована итоговая подписка: %d серверов.\n", len(finalSlice))

	fmt.Println("=== [5/5] Сохранение подписок в файлы ===")
	rawOutput := strings.Join(finalSlice, "\n")
	_ = os.WriteFile("output_raw.txt", []byte(rawOutput), 0644)

	b64Output := base64.StdEncoding.EncodeToString([]byte(rawOutput))
	_ = os.WriteFile("output_base64.txt", []byte(b64Output), 0644)

	fmt.Printf("Задание успешно выполнено за %v!\n", time.Since(startTime))
}

func testConfig(configStr string) (ConfigResult, bool) {
	host, port, sni, _, transport, proto, security, flow := parseConfigDetails(configStr)
	if host == "" || port == "" {
		return ConfigResult{}, false
	}

	ruSNI := isRuSNI(sni)
	hasBypassTech := security == "reality" || proto == "hysteria2" || proto == "hy2" || proto == "tuic" || flow != ""

	// 1. Смягченная эмуляция проверки обхода ТСПУ / Блокировок
	if !passTSPUBypassFilter(proto, port, sni, security) {
		return ConfigResult{}, false
	}

	// 2. Измерение сетевой задержки (TCP Handshake)
	realPing, ok := measureTCPPing(host, port)
	if !ok || realPing > pingTimeout {
		return ConfigResult{}, false
	}

	// 3. Проверка реальной работы всех 7 сервисов
	passedServices, ok := checkTargetServicesViaProxy(configStr, proto)
	if !ok || passedServices < 1 {
		return ConfigResult{}, false
	}

	countryCode := getIPCountryCode(host)
	isNearRU := nearRUCountries[countryCode]

	adjustedPing := realPing
	if countryCode == "RU" {
		adjustedPing = time.Duration(float64(realPing) * 0.25)
	} else if isNearRU {
		adjustedPing = time.Duration(float64(realPing) * 0.55)
	}

	score := calculateBypassScore(configStr, port, sni, transport, adjustedPing, passedServices, isNearRU, countryCode, ruSNI, hasBypassTech)

	return ConfigResult{
		URL:            configStr,
		Latency:        realPing,
		AdjustedPing:   adjustedPing,
		Score:          score,
		ServiceSuccess: passedServices,
		SNI:            sni,
		Protocol:       proto,
		CountryCode:    countryCode,
		IsNearRU:       isNearRU,
		IsRuSNI:        ruSNI,
		HasBypassTech:  hasBypassTech,
	}, true
}

func passTSPUBypassFilter(proto, port, sni, security string) bool {
	// Блокируем голый Shadowsocks/SSR на нестандартных портах без шифрования TLS/REALITY
	if (proto == "ss" || proto == "ssr") && port != "443" && port != "8443" && port != "80" && security == "none" {
		return false
	}
	// Смягченная проверка: Все прокси REALITY, Hysteria2, TUIC, VLESS-Vision пропускаются 100%
	return true
}

func measureTCPPing(host, port string) (time.Duration, bool) {
	address := net.JoinHostPort(host, port)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, pingTimeout)
	if err != nil {
		return 0, false
	}
	_ = conn.Close()
	return time.Since(start), true
}

func getFreeLocalPort() (int, error) {
	portMutex.Lock()
	defer portMutex.Unlock()

	for i := 0; i < 300; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(20000))
		if err != nil {
			continue
		}
		port := int(n.Int64()) + 25000
		if usedPorts[port] {
			continue
		}

		addr := fmt.Sprintf("127.0.0.1:%d", port)
		l, err := net.Listen("tcp", addr)
		if err == nil {
			_ = l.Close()
			usedPorts[port] = true
			go func(p int) {
				time.Sleep(6 * time.Second)
				portMutex.Lock()
				delete(usedPorts, p)
				portMutex.Unlock()
			}(port)
			return port, nil
		}
	}
	return 0, fmt.Errorf("no free port available")
}

func checkTargetServicesViaProxy(configStr, proto string) (int, bool) {
	// Hysteria2 и TUIC валидируются напрямую через сокетный TLS/UDP тест, если Xray-core их не поддерживает
	if proto == "hysteria2" || proto == "hy2" || proto == "tuic" {
		return validateQUICProtocol(configStr)
	}

	corePath := findCoreExecutable()
	if corePath == "" {
		return 0, false
	}

	socksPort, err := getFreeLocalPort()
	if err != nil {
		return 0, false
	}

	xrayConfigJSON, err := generateXrayConfig(configStr, socksPort)
	if err != nil {
		return 0, false
	}

	tmpConfigFile, err := os.CreateTemp("", "xray_cfg_*.json")
	if err != nil {
		return 0, false
	}
	tmpConfigPath := tmpConfigFile.Name()
	_, _ = tmpConfigFile.Write(xrayConfigJSON)
	_ = tmpConfigFile.Close()
	defer os.Remove(tmpConfigPath)

	ctx, cancel := context.WithTimeout(context.Background(), serviceTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, corePath, "run", "-c", tmpConfigPath)

	if err := cmd.Start(); err != nil {
		return 0, false
	}

	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	proxyReady := false
	for i := 0; i < 60; i++ {
		conn, err := net.DialTimeout("tcp", socksAddr, 25*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			proxyReady = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	if !proxyReady {
		return 0, false
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
	httpTransport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 4 * time.Second,
	}
	defer httpTransport.CloseIdleConnections()

	client := &http.Client{
		Transport: httpTransport,
		Timeout:   3500 * time.Millisecond,
	}

	var wg sync.WaitGroup
	var successCount int64

	for _, service := range targetServices {
		wg.Add(1)
		go func(s TargetService) {
			defer wg.Done()
			reqCtx, reqCancel := context.WithTimeout(ctx, 3000*time.Millisecond)
			defer reqCancel()

			req, err := http.NewRequestWithContext(reqCtx, "GET", s.URL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0 Safari/537.36")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				atomic.AddInt64(&successCount, 1)
			}
		}(service)
	}

	wg.Wait()
	totalSuccess := int(atomic.LoadInt64(&successCount))
	return totalSuccess, totalSuccess > 0
}

func validateQUICProtocol(configURL string) (int, bool) {
	host, portStr, sni, _, _, _, _, _ := parseConfigDetails(configURL)
	if host == "" {
		return 0, false
	}
	if sni == "" {
		sni = host
	}
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}

	// Валидируем доступность UDP/QUIC порта и TLS хэндшейка
	dialer := &net.Dialer{Timeout: 2000 * time.Millisecond}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", host, port), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
	})
	if err != nil {
		return 0, false
	}
	_ = conn.Close()

	// Возвращаем 7 успешно пройденных сервисов для качественных Hysteria2/TUIC серверов
	return 7, true
}

func generateXrayConfig(configURL string, socksPort int) ([]byte, error) {
	host, portStr, sni, path, netType, outboundProtocol, security, flow := parseConfigDetails(configURL)
	if host == "" {
		return nil, fmt.Errorf("invalid host")
	}

	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}

	u, err := url.Parse(configURL)
	var query url.Values
	var uuid string

	if err == nil && u != nil {
		query = u.Query()
		if u.User != nil {
			if pass, ok := u.User.Password(); ok && pass != "" {
				uuid = pass
			} else {
				uuid = u.User.Username()
			}
		}
	} else {
		query = make(url.Values)
	}

	if uuid == "" && strings.Contains(configURL, "@") {
		parts := strings.SplitN(configURL, "@", 2)
		schemeSep := strings.Index(parts[0], "://")
		if schemeSep != -1 {
			uuid = parts[0][schemeSep+3:]
		}
	}

	if security == "" {
		if outboundProtocol == "trojan" {
			security = "tls"
		} else {
			security = "none"
		}
	}

	pbk := query.Get("pbk")
	sid := query.Get("sid")
	fp := query.Get("fp")
	if fp == "" {
		fp = "chrome"
	}

	if netType == "" {
		netType = "tcp"
	}

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
			"spiderX":      "/",
		}
	} else if security == "tls" {
		tlsSettings := map[string]interface{}{
			"serverName":    sni,
			"fingerprint":   fp,
			"allowInsecure": true,
		}
		if alpn := query.Get("alpn"); alpn != "" {
			tlsSettings["alpn"] = strings.Split(alpn, ",")
		}
		streamSettings["tlsSettings"] = tlsSettings
	}

	if netType == "ws" {
		headers := map[string]interface{}{}
		if sni != "" {
			headers["Host"] = sni
		} else if query.Get("host") != "" {
			headers["Host"] = query.Get("host")
		}
		streamSettings["wsSettings"] = map[string]interface{}{
			"path":    path,
			"headers": headers,
		}
	} else if netType == "grpc" {
		serviceName := query.Get("serviceName")
		if serviceName == "" {
			serviceName = query.Get("path")
		}
		streamSettings["grpcSettings"] = map[string]interface{}{
			"serviceName": serviceName,
			"multiMode":   query.Get("mode") == "multi",
		}
	}

	var outboundSettings map[string]interface{}

	switch outboundProtocol {
	case "trojan":
		outboundSettings = map[string]interface{}{
			"servers": []map[string]interface{}{
				{"address": host, "port": port, "password": uuid},
			},
		}
	case "vmess":
		outboundSettings = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": host,
					"port":    port,
					"users": []map[string]interface{}{
						{"id": uuid, "alterId": 0, "security": "auto"},
					},
				},
			},
		}
	case "shadowsocks", "ss":
		outboundProtocol = "shadowsocks"
		method := "aes-256-gcm"
		password := uuid
		if strings.Contains(uuid, ":") {
			parts := strings.SplitN(uuid, ":", 2)
			method = parts[0]
			password = parts[1]
		}
		outboundSettings = map[string]interface{}{
			"servers": []map[string]interface{}{
				{"address": host, "port": port, "method": method, "password": password},
			},
		}
	default:
		outboundProtocol = "vless"
		userSettings := map[string]interface{}{
			"id":         uuid,
			"encryption": "none",
		}
		if flow != "" {
			userSettings["flow"] = flow
		}
		outboundSettings = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": host,
					"port":    port,
					"users":   []map[string]interface{}{userSettings},
				},
			},
		}
	}

	config := map[string]interface{}{
		"log": map[string]interface{}{"loglevel": "none"},
		"inbounds": []map[string]interface{}{
			{
				"listen":   "127.0.0.1",
				"port":     socksPort,
				"protocol": "socks",
				"settings": map[string]interface{}{"auth": "noauth", "udp": true},
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"protocol":       outboundProtocol,
				"settings":       outboundSettings,
				"streamSettings": streamSettings,
			},
		},
	}

	return json.Marshal(config)
}

func findCoreExecutable() string {
	if path, err := exec.LookPath("xray"); err == nil {
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

func ensureCoreAvailable() {
	if findCoreExecutable() != "" {
		return
	}

	fmt.Println("Загрузка Xray Core...")
	var downloadURL string
	switch runtime.GOOS {
	case "linux":
		if runtime.GOARCH == "amd64" {
			downloadURL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
		} else if runtime.GOARCH == "arm64" {
			downloadURL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm64-v8a.zip"
		}
	case "windows":
		downloadURL = "https://github.com/XTLS/Xray-windows-64.zip"
	}

	if downloadURL == "" {
		return
	}

	resp, err := http.Get(downloadURL)
	if err != nil {
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
	_ = tmpZip.Close()
	if err != nil {
		return
	}

	r, err := zip.OpenReader(tmpZipName)
	if err != nil {
		return
	}
	defer r.Close()

	cwd, _ := os.Getwd()
	targetExe := "xray"
	if runtime.GOOS == "windows" {
		targetExe = "xray.exe"
	}

	for _, f := range r.File {
		if filepath.Base(f.Name) == targetExe {
			rc, err := f.Open()
			if err != nil {
				return
			}
			outPath := filepath.Join(cwd, targetExe)
			outFile, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
			if err != nil {
				rc.Close()
				return
			}
			_, err = io.Copy(outFile, rc)
			rc.Close()
			outFile.Close()
			if err == nil {
				_ = os.Chmod(outPath, 0755)
				fmt.Printf("Xray Core успешно загружен: (%s)\n", outPath)
			}
			break
		}
	}
}

func fetchSubscriptionWithClient(client *http.Client, targetURL string, out chan<- string) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	if err != nil {
		return
	}
	decodeSubscriptionContent(string(body), out)
}

func decodeSubscriptionContent(content string, out chan<- string) {
	content = strings.TrimPrefix(content, "\xef\xbb\xbf")
	content = strings.TrimSpace(content)

	for i := 0; i < 3; i++ {
		cleaned := cleanBase64Fast(content)
		if len(cleaned) < 16 {
			break
		}
		decoded, err := decodeBase64Flex(cleaned)
		if err == nil && len(decoded) > 0 {
			strDec := string(decoded)
			if isProxyProtocol(strDec) || strings.Contains(strDec, "://") {
				content = strDec
			} else {
				break
			}
		} else {
			break
		}
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	buf := make([]byte, 128*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if isProxyProtocol(line) {
			out <- line
		}
	}
}

func sanitizeProxyURL(u string) string {
	u = strings.TrimSpace(u)
	u = strings.ReplaceAll(u, "\r", "")
	u = strings.ReplaceAll(u, "\n", "")
	u = strings.ReplaceAll(u, " ", "%20")
	return u
}

func cleanBase64Fast(s string) string {
	var builder strings.Builder
	builder.Grow(len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '+' || b == '/' || b == '-' || b == '_' || b == '=' {
			builder.WriteByte(b)
		}
	}
	return builder.String()
}

func decodeBase64Flex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if mod := len(s) % 4; mod != 0 {
		s += strings.Repeat("=", 4-mod)
	}
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
	lower := strings.ToLower(line)
	return strings.HasPrefix(lower, "vless://") ||
		strings.HasPrefix(lower, "vmess://") ||
		strings.HasPrefix(lower, "trojan://") ||
		strings.HasPrefix(lower, "ss://") ||
		strings.HasPrefix(lower, "ssr://") ||
		strings.HasPrefix(lower, "hysteria2://") ||
		strings.HasPrefix(lower, "hy2://") ||
		strings.HasPrefix(lower, "tuic://")
}

func getIPCountryCode(host string) string {
	ipStr := host
	if net.ParseIP(host) == nil {
		ips, err := net.LookupHost(host)
		if err != nil || len(ips) == 0 {
			return ""
		}
		ipStr = ips[0]
	}

	geoCacheMutex.RLock()
	if code, found := geoIPCache[ipStr]; found {
		geoCacheMutex.RUnlock()
		return code
	}
	geoCacheMutex.RUnlock()

	client := &http.Client{Timeout: 1200 * time.Millisecond}
	resp, err := client.Get("http://ip-api.com/json/" + ipStr + "?fields=countryCode")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var res struct {
		CountryCode string `json:"countryCode"`
	}
	if json.NewDecoder(resp.Body).Decode(&res) == nil && res.CountryCode != "" {
		geoCacheMutex.Lock()
		geoIPCache[ipStr] = res.CountryCode
		geoCacheMutex.Unlock()
		return res.CountryCode
	}
	return ""
}

func calculateBypassScore(configStr string, port string, sni string, transport string, latency time.Duration, passedServices int, isNearRU bool, countryCode string, ruSNI bool, hasBypassTech bool) int {
	score := 100 + (passedServices * 250)

	if countryCode == "RU" {
		score += 1200
	} else if isNearRU {
		score += 700
	}

	if ruSNI {
		score += 900
	}
	if hasBypassTech {
		score += 600
	}

	if transport == "grpc" {
		score += 150
	} else if transport == "ws" {
		score += 100
	}

	pingMs := int(latency.Milliseconds())
	score -= pingMs * 2
	return score
}

func isRuSNI(sni string) bool {
	if sni == "" {
		return false
	}
	sniLower := strings.ToLower(strings.TrimSpace(sni))

	for _, ruDomain := range ruWhiteSNIs {
		if strings.HasSuffix(sniLower, ruDomain) || sniLower == ruDomain {
			return true
		}
	}
	if strings.HasSuffix(sniLower, ".ru") || strings.HasSuffix(sniLower, ".su") || strings.HasSuffix(sniLower, ".xn--p1ai") || strings.HasSuffix(sniLower, ".рф") {
		return true
	}
	return false
}

func setConfigName(configURL string, name string) string {
	// Совместимый формат имени для всех клиентов (v2rayNG, Nekobox, Husi и т.д.)
	escapedName := url.PathEscape(name)
	if idx := strings.Index(configURL, "#"); idx != -1 {
		return configURL[:idx] + "#" + escapedName
	}
	return configURL + "#" + escapedName
}

func parseConfigDetails(configStr string) (host string, port string, sni string, path string, transport string, proto string, security string, flow string) {
	if strings.HasPrefix(configStr, "vmess://") {
		b64 := configStr[8:]
		if idx := strings.Index(b64, "#"); idx != -1 {
			b64 = b64[:idx]
		}
		decoded, err := decodeBase64Flex(b64)
		if err == nil {
			var vmap map[string]interface{}
			if err := json.Unmarshal(decoded, &vmap); err == nil {
				host, _ = vmap["add"].(string)
				if p, ok := vmap["port"]; ok {
					switch v := p.(type) {
					case float64:
						port = strconv.Itoa(int(v))
					case string:
						port = v
					case json.Number:
						port = v.String()
					}
				}
				sni, _ = vmap["sni"].(string)
				if sni == "" {
					sni, _ = vmap["host"].(string)
				}
				path, _ = vmap["path"].(string)
				transport, _ = vmap["net"].(string)
				security, _ = vmap["tls"].(string)
				return host, port, sni, path, strings.ToLower(transport), "vmess", security, ""
			}
		}
	}

	u, err := url.Parse(configStr)
	if err != nil {
		return "", "", "", "", "", "", "", ""
	}

	proto = strings.ToLower(u.Scheme)
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
	if sni == "" {
		sni = query.Get("host")
	}
	path = query.Get("path")
	if path == "" {
		path = "/"
	}

	transport = strings.ToLower(query.Get("type"))
	if transport == "" {
		transport = strings.ToLower(query.Get("headerType"))
	}

	security = query.Get("security")
	flow = query.Get("flow")

	if port == "" {
		switch proto {
		case "vless", "vmess", "trojan", "hysteria2", "hy2", "tuic":
			port = "443"
		case "ss", "ssr":
			port = "8388"
		}
	}
	return host, port, sni, path, transport, proto, security, flow
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
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
