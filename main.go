package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	timeout        = 1200 * time.Millisecond
	serviceTimeout = 3800 * time.Millisecond
	maxConcurrency = 180
	maxOutputLimit = 300

	// --- НАСТРОЙКИ ЖЕСТКОЙ ФИЛЬТРАЦИИ ---
	StrictRuSNIOnly = false
	StrictVLESSOnly = false
	StrictPortsOnly = false
)

type ConfigResult struct {
	URL            string
	CleanURL       string
	Latency        time.Duration
	Score          int
	ServiceSuccess int
	SNI            string
	Protocol       string
	IsRuSNI        bool
	IsNoSNI        bool
	IsReality      bool
}

type TargetService struct {
	Name string
	URL  string
}

var mandatoryServiceNames = []string{
	"Google", "YouTube", "Instagram", "Telegram", "WhatsApp", "Viber", "GitHub",
}

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

// Расширенный белый список SNI и инфраструктурных доменов для гарантированного прохождения проверки ТСПУ
var ruWhiteSNIs = []string{
	// Государственные ресурсы и инфраструктура
	"gosuslugi.ru", "mos.ru", "nalog.gov.ru", "cbr.ru", "kremlin.ru",
	// Крупнейшие порталы, экосистемы и поисковики
	"yandex.ru", "ya.ru", "dzen.ru", "yastatic.net", "yandex.net",
	"vk.com", "vk.me", "vk-portal.net", "cdn.vk.com", "ok.ru", "mail.ru", "rambler.ru",
	// Банки и финансовый сектор
	"sberbank.ru", "tbank.ru", "tinkoff.ru", "vtb.ru", "alfabank.ru", "open.ru", "mirconnect.ru",
	// Маркетплейсы и ритейл
	"ozon.ru", "wildberries.ru", "wb.ru", "avito.ru", "ecom.ozon.ru",
	// Медиа, видеохостинги и операторы
	"kinopoisk.ru", "rutube.ru", "hh.ru", "rbc.ru", "ria.ru", "lenta.ru", "gazeta.ru",
	"rt.ru", "megafon.ru", "beeline.ru", "mts.ru", "nornickel.ru", "maxima.ru",
}

// Заблокированные или жестко фильтруемые зарубежные SNI
var blockedGlobalSNIs = []string{
	"cloudflare.com", "cloudfront.net", "google.com", "facebook.com",
	"discord.gg", "discord.com", "twitter.com", "x.com", "instagram.com",
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	startTime := time.Now()

	fmt.Println("=== [1/5] Инициализация высокоскоростного окружения и Xray Core ===")
	ensureCoreAvailable()

	sources, err := readLines("sources.txt")
	if err != nil {
		fmt.Printf("Ошибка чтения sources.txt: %v. Создаем пустые выходные файлы.\n", err)
		_ = os.WriteFile("output_raw.txt", []byte(""), 0644)
		_ = os.WriteFile("output_base64.txt", []byte(""), 0644)
		return
	}

	fmt.Printf("Загружено источников подписок: %d\n", len(sources))
	fmt.Println("=== [2/5] Быстрый асинхронный сбор и декодирование прокси-конфигураций ===")

	rawConfigs := make(chan string, 3000000)
	var wg sync.WaitGroup

	sharedHTTPClient := &http.Client{
		Timeout: 7 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:          20000,
			MaxIdleConnsPerHost:   2000,
			IdleConnTimeout:       30 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			DisableKeepAlives:     false,
		},
	}

	for _, src := range sources {
		src = strings.TrimSpace(src)
		if src == "" || strings.HasPrefix(src, "#") {
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

	uniqueConfigs := make(map[string]string)
	for cfg := range rawConfigs {
		cfg = strings.TrimSpace(cfg)
		if cfg != "" && len(cfg) < 4096 {
			cleanCfg := stripConfigTag(cfg)
			hash := md5Hash(cleanCfg)
			if _, exists := uniqueConfigs[hash]; !exists {
				uniqueConfigs[hash] = cfg
			}
		}
	}

	totalConfigs := len(uniqueConfigs)
	fmt.Printf("Собрано %d уникальных прокси-ссылок.\n", totalConfigs)
	fmt.Println("=== [3/5] Запуск эмуляции ТСПУ, Белых списков & Доступности сервисов ===")

	resultsChan := make(chan ConfigResult, totalConfigs)
	semaphore := make(chan struct{}, maxConcurrency)
	var testWg sync.WaitGroup
	var processedCount int64

	for _, cfg := range uniqueConfigs {
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
				fmt.Printf("Проверено узлов: %d / %d\r", curr, totalConfigs)
			}
		}(cfg)
	}

	testWg.Wait()
	close(resultsChan)
	fmt.Println("\nТестирование всех узлов завершено.")

	var validResults []ConfigResult
	for res := range resultsChan {
		if res.Score > 0 {
			validResults = append(validResults, res)
		}
	}

	fmt.Printf("=== [4/5] Балансировка подписки (>55%% RU SNI) (Валидных: %d) ===\n", len(validResults))

	var ruSNIConfigs []ConfigResult
	var noSNIConfigs []ConfigResult
	var realityConfigs []ConfigResult
	var otherConfigs []ConfigResult

	for _, res := range validResults {
		if res.IsRuSNI {
			ruSNIConfigs = append(ruSNIConfigs, res)
		} else if res.IsReality {
			realityConfigs = append(realityConfigs, res)
		} else if res.IsNoSNI {
			noSNIConfigs = append(noSNIConfigs, res)
		} else {
			otherConfigs = append(otherConfigs, res)
		}
	}

	sortByScore := func(slice []ConfigResult) {
		sort.Slice(slice, func(i, j int) bool {
			if slice[i].ServiceSuccess == slice[j].ServiceSuccess {
				if slice[i].Score == slice[j].Score {
					return slice[i].Latency < slice[j].Latency
				}
				return slice[i].Score > slice[j].Score
			}
			return slice[i].ServiceSuccess > slice[j].ServiceSuccess
		})
	}

	sortByScore(ruSNIConfigs)
	sortByScore(realityConfigs)
	sortByScore(noSNIConfigs)
	sortByScore(otherConfigs)

	fmt.Printf("Доступно по категориям: [RU SNI: %d] | [REALITY: %d] | [No-SNI: %d] | [Прочие: %d]\n",
		len(ruSNIConfigs), len(realityConfigs), len(noSNIConfigs), len(otherConfigs))

	var selected []ConfigResult
	usedMap := make(map[string]bool)

	addUnique := func(item ConfigResult) bool {
		if len(selected) >= maxOutputLimit {
			return false
		}
		clean := stripConfigTag(item.URL)
		if !usedMap[clean] {
			selected = append(selected, item)
			usedMap[clean] = true
			return true
		}
		return false
	}

	// Квота RU SNI = 55%
	ruTargetQuota := (maxOutputLimit * 55) / 100
	for i := 0; i < len(ruSNIConfigs) && len(selected) < ruTargetQuota; i++ {
		addUnique(ruSNIConfigs[i])
	}

	remainingQuota := maxOutputLimit - len(selected)
	perOtherCategory := remainingQuota / 3
	if perOtherCategory < 1 {
		perOtherCategory = 1
	}

	for i := 0; i < perOtherCategory && i < len(realityConfigs); i++ {
		addUnique(realityConfigs[i])
	}
	for i := 0; i < perOtherCategory && i < len(noSNIConfigs); i++ {
		addUnique(noSNIConfigs[i])
	}
	for i := 0; i < perOtherCategory && i < len(otherConfigs); i++ {
		addUnique(otherConfigs[i])
	}

	for _, res := range ruSNIConfigs {
		addUnique(res)
	}
	for _, res := range realityConfigs {
		addUnique(res)
	}
	for _, res := range noSNIConfigs {
		addUnique(res)
	}
	for _, res := range otherConfigs {
		addUnique(res)
	}

	var finalSlice []string
	for i, r := range selected {
		renamedURL := setConfigName(r.URL, fmt.Sprintf("Sub %d", i+1))
		finalSlice = append(finalSlice, renamedURL)
	}

	fmt.Printf("Сформирован итоговый МИКС из %d прокси-конфигураций.\n", len(finalSlice))

	fmt.Println("=== [5/5] Запись выходных файлов подписок ===")
	rawOutput := strings.Join(finalSlice, "\n")
	_ = os.WriteFile("output_raw.txt", []byte(rawOutput), 0644)

	b64Output := base64.StdEncoding.EncodeToString([]byte(rawOutput))
	_ = os.WriteFile("output_base64.txt", []byte(b64Output), 0644)

	fmt.Printf("Процесс успешно завершен за %v! Файлы output_raw.txt и output_base64.txt готовы.\n", time.Since(startTime))
}

func testConfig(configStr string) (ConfigResult, bool) {
	host, port, sni, path, transport, proto := parseConfigDetails(configStr)
	if host == "" || port == "" {
		return ConfigResult{}, false
	}

	lowerCfg := strings.ToLower(configStr)

	if StrictPortsOnly && port != "443" && port != "80" && port != "8443" && port != "2053" && port != "2083" {
		return ConfigResult{}, false
	}

	if StrictVLESSOnly && proto != "vless" {
		return ConfigResult{}, false
	}

	if StrictRuSNIOnly && !isRuSNI(sni) {
		return ConfigResult{}, false
	}

	// 1. Эмуляция проверок ТСПУ и белых списков
	if !simulateTSPUBypassCheck(proto, port, sni, lowerCfg) {
		return ConfigResult{}, false
	}

	targetAddr := net.JoinHostPort(host, port)
	start := time.Now()

	// 2. Первичная экспресс-проверка TCP/TLS
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return ConfigResult{}, false
	}

	serverName := sni
	if serverName == "" {
		serverName = host
	}

	var conn net.Conn = rawConn
	isTLS := strings.Contains(lowerCfg, "security=tls") || strings.Contains(lowerCfg, "security=reality") || proto == "trojan" || proto == "hysteria2" || proto == "hy2" || proto == "tuic"

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

		buf := make([]byte, 512)
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

	// 3. Проверка через Xray Core
	passedServices, mandatoryPassed := checkTargetServicesViaProxy(configStr)
	if !mandatoryPassed {
		return ConfigResult{}, false
	}

	isReality := strings.Contains(lowerCfg, "security=reality")
	ruSNI := isRuSNI(sni)
	noSNI := isNoSNI(sni, host)
	score := calculateBypassScore(configStr, port, sni, transport, latency, passedServices)

	return ConfigResult{
		URL:            configStr,
		CleanURL:       stripConfigTag(configStr),
		Latency:        latency,
		Score:          score,
		ServiceSuccess: passedServices,
		SNI:            sni,
		Protocol:       proto,
		IsRuSNI:        ruSNI,
		IsNoSNI:        noSNI,
		IsReality:      isReality,
	}, true
}

// Эмуляция алгоритмов ТСПУ
func simulateTSPUBypassCheck(proto, port, sni, lowerCfg string) bool {
	ruSNI := isRuSNI(sni)
	isReality := strings.Contains(lowerCfg, "security=reality")
	isTLS := strings.Contains(lowerCfg, "security=tls")

	// 1. Фильтрация открытых протоколов без TLS на нестандартных портах
	// ТСПУ анализирует незашифрованный трафик и активнее блокирует нетипичные порты.
	if !isTLS && !isReality && port != "80" && port != "8080" && port != "8880" && port != "2052" && port != "2082" && port != "2086" && port != "2095" {
		return false
	}

	// 2. Блокировка незашифрованных или легко определяемых протоколов (Shadowsocks/SSR без плагинов маскировки)
	if proto == "ss" || proto == "ssr" {
		if !ruSNI && !isReality && !strings.Contains(lowerCfg, "plugin=") {
			return false
		}
	}

	// 3. Проверка белых / черных списков SNI для стандартного TLS
	// Если используется обычный TLS (не Reality), SNI проверяется по правилам белого списка.
	if isTLS && !isReality {
		// Блокировка явных зарубежных SNI из черного списка
		for _, b := range blockedGlobalSNIs {
			if strings.Contains(sni, b) {
				return false
			}
		}

		// Если SNI указан, но не входит в разрешенную RU-зону / белый список, шанс блокировки ТСПУ высокий
		if sni != "" && !ruSNI {
			// Допускаем только IP в качестве host или разрешенные белые домены
			if net.ParseIP(sni) == nil {
				return false
			}
		}
	}

	return true
}

func checkTargetServicesViaProxy(configStr string) (int, bool) {
	corePath := findCoreExecutable()
	if corePath == "" {
		return 0, false
	}

	socksPort := getFreeTCPPort()
	if socksPort == 0 {
		return 0, false
	}

	xrayConfigJSON, err := generateXrayConfig(configStr, socksPort)
	if err != nil {
		return 0, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), serviceTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, corePath, "run", "-c", "stdin:")
	cmd.Stdin = bytes.NewReader(xrayConfigJSON)
	cmd.Stdout = nil
	cmd.Stderr = nil

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

	for i := 0; i < 30; i++ {
		conn, err := net.DialTimeout("tcp", socksAddr, 8*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			proxyReady = true
			break
		}
		time.Sleep(6 * time.Millisecond)
	}

	if !proxyReady {
		return 0, false
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
	httpTransport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: 20,
	}

	client := &http.Client{
		Transport: httpTransport,
		Timeout:   serviceTimeout - (400 * time.Millisecond),
	}

	var wg sync.WaitGroup
	var successCount int64

	mandatoryPassedMap := make(map[string]bool)
	for _, name := range mandatoryServiceNames {
		mandatoryPassedMap[name] = false
	}
	var mapMutex sync.Mutex

	for _, service := range targetServices {
		wg.Add(1)
		go func(s TargetService) {
			defer wg.Done()

			req, err := http.NewRequestWithContext(ctx, "GET", s.URL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				atomic.AddInt64(&successCount, 1)
				mapMutex.Lock()
				if _, exists := mandatoryPassedMap[s.Name]; exists {
					mandatoryPassedMap[s.Name] = true
				}
				mapMutex.Unlock()
			}
		}(service)
	}

	wg.Wait()

	allMandatoryPassed := true
	for _, name := range mandatoryServiceNames {
		if !mandatoryPassedMap[name] {
			allMandatoryPassed = false
			break
		}
	}

	return int(atomic.LoadInt64(&successCount)), allMandatoryPassed
}

func generateXrayConfig(configURL string, socksPort int) ([]byte, error) {
	host, portStr, sni, path, netType, outboundProtocol := parseConfigDetails(configURL)
	if host == "" {
		return nil, fmt.Errorf("invalid host")
	}

	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}

	u, err := url.Parse(configURL)
	if err != nil {
		return nil, err
	}

	query := u.Query()
	uuid := u.User.Username()

	security := query.Get("security")
	if security == "" {
		if outboundProtocol == "trojan" || outboundProtocol == "hysteria2" || outboundProtocol == "hy2" || outboundProtocol == "tuic" {
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
		wsHeaders := map[string]interface{}{}
		if sni != "" {
			wsHeaders["Host"] = sni
		}
		streamSettings["wsSettings"] = map[string]interface{}{
			"path":    path,
			"headers": wsHeaders,
		}
	} else if netType == "grpc" {
		streamSettings["grpcSettings"] = map[string]interface{}{
			"serviceName": query.Get("serviceName"),
		}
	}

	var outboundSettings map[string]interface{}

	switch outboundProtocol {
	case "trojan":
		outboundSettings = map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  host,
					"port":     port,
					"password": uuid,
				},
			},
		}
	case "shadowsocks":
		userPass := u.User.String()
		method := "aes-128-gcm"
		password := userPass

		if strings.Contains(userPass, ":") {
			parts := strings.SplitN(userPass, ":", 2)
			method = parts[0]
			password = parts[1]
		} else if dec, err := decodeBase64Flex(userPass); err == nil && strings.Contains(string(dec), ":") {
			parts := strings.SplitN(string(dec), ":", 2)
			method = parts[0]
			password = parts[1]
		}

		outboundSettings = map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  host,
					"port":     port,
					"method":   method,
					"password": password,
				},
			},
		}
	case "hysteria2", "hy2":
		outboundSettings = map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  host,
					"port":     port,
					"password": uuid,
				},
			},
		}
	default: // vless / vmess
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
				"protocol":       outboundProtocol,
				"settings":       outboundSettings,
				"streamSettings": streamSettings,
			},
		},
	}

	return json.Marshal(config)
}

func getFreeTCPPort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
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

func ensureCoreAvailable() {
	if findCoreExecutable() != "" {
		return
	}

	fmt.Println("Бинарник Xray/sing-box не найден. Автоматическая загрузка Xray Core...")

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
		fmt.Println("Предупреждение: Неподдерживаемая ОС/архитектура для автоматической загрузки Xray.")
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
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 25*1024*1024))
	if err != nil {
		return
	}

	content := string(body)
	if decoded, err := decodeBase64Flex(cleanBase64Fast(content)); err == nil && len(decoded) > 0 {
		content = string(decoded)
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 5*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if isProxyProtocol(line) {
			out <- line
		}
	}
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

func calculateBypassScore(configStr string, port string, sni string, transport string, latency time.Duration, passedServices int) int {
	score := 100 + (passedServices * 70)
	lower := strings.ToLower(configStr)

	if strings.Contains(lower, "security=reality") {
		score += 300
	}

	if isRuSNI(sni) {
		score += 250
	}

	if transport == "grpc" {
		score += 90
	} else if transport == "ws" {
		score += 50
	}

	pingMs := int(latency.Milliseconds())
	score -= pingMs / 3

	return score
}

// Улучшенная проверка на принадлежность к белым RU-доменам
func isRuSNI(sni string) bool {
	if sni == "" {
		return false
	}
	sniLower := strings.ToLower(strings.TrimSpace(sni))

	for _, ruDomain := range ruWhiteSNIs {
		if sniLower == ruDomain || strings.HasSuffix(sniLower, "."+ruDomain) {
			return true
		}
	}

	if strings.HasSuffix(sniLower, ".ru") || strings.HasSuffix(sniLower, ".su") || strings.HasSuffix(sniLower, ".xn--p1ai") || strings.HasSuffix(sniLower, ".рф") {
		return true
	}

	return false
}

func isNoSNI(sni string, host string) bool {
	if sni == "" {
		return true
	}
	if net.ParseIP(sni) != nil || net.ParseIP(host) != nil {
		return true
	}
	return false
}

func stripConfigTag(configURL string) string {
	if idx := strings.Index(configURL, "#"); idx != -1 {
		return configURL[:idx]
	}
	return configURL
}

func md5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func setConfigName(configURL string, name string) string {
	escapedName := url.PathEscape(name)
	if idx := strings.Index(configURL, "#"); idx != -1 {
		return configURL[:idx] + "#" + escapedName
	}
	return configURL + "#" + escapedName
}

func parseConfigDetails(configStr string) (host string, port string, sni string, path string, transport string, proto string) {
	if strings.HasPrefix(configStr, "vmess://") {
		b64 := configStr[8:]
		decoded, err := decodeBase64Flex(b64)
		if err == nil {
			var vmap map[string]interface{}
			if err := json.Unmarshal(decoded, &vmap); err == nil {
				host, _ = vmap["add"].(string)
				if p, ok := vmap["port"]; ok {
					switch v := p.(type) {
					case float64:
						port = fmt.Sprintf("%.0f", v)
					case string:
						port = v
					default:
						port = fmt.Sprintf("%v", v)
					}
				}
				sni, _ = vmap["sni"].(string)
				if sni == "" {
					sni, _ = vmap["host"].(string)
				}
				path, _ = vmap["path"].(string)
				transport, _ = vmap["net"].(string)
				return host, port, sni, path, strings.ToLower(transport), "vmess"
			}
		}
	}

	u, err := url.Parse(configStr)
	if err != nil {
		return "", "", "", "", "", ""
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

	path = query.Get("path")
	if path == "" {
		path = "/"
	}

	transport = strings.ToLower(query.Get("type"))
	if transport == "" {
		transport = strings.ToLower(query.Get("headerType"))
	}

	if port == "" {
		switch proto {
		case "vless", "vmess", "trojan", "hysteria2", "hy2", "tuic":
			port = "443"
		case "ss":
			port = "8388"
		}
	}

	return host, port, sni, path, transport, proto
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
