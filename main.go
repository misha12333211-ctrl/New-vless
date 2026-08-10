package main

import (
	"archive/zip"
	"bufio"
	"bytes"
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
	// Жесткий тайм-аут для проверки низкого пинга (50-70 мс на симке)
	timeout        = 2000 * time.Millisecond
	serviceTimeout = 6000 * time.Millisecond
	maxConcurrency = 100 // Максимальный параллелизм для быстрого отсева
	maxOutputLimit = 300 // Оптимальный объем подписки

	// Максимально допустимый пинг из Runner (Европа), чтобы на симке в РФ было ~50-70 мс
	maxAllowedRunnerLatency = 45 * time.Millisecond

	StrictRuSNIOnly = false
	StrictVLESSOnly = false
	StrictPortsOnly = false
)

type ConfigResult struct {
	URL            string
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

// 7 Обязательных сервисов для обхода блокировок
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

// Расширенный список белых SNI для обхода ТСПУ 2026
var ruWhiteSNIs = []string{
	// Экосистема VK & Mail.ru
	"vk.com", "vk.me", "m.vk.com", "userapi.com", "vk-cdn.net", "mail.ru", "ok.ru", "my.games", "vkplay.ru", "vkcompany.ru",
	// Экосистема Yandex
	"yandex.ru", "ya.ru", "yastatic.net", "yandex.net", "kinopoisk.ru", "music.yandex.ru", "disk.yandex.ru", "yandex.com",
	// Банки и Финансы
	"sberbank.ru", "sber.ru", "online.sberbank.ru", "tbank.ru", "tinkoff.ru", "vtb.ru", "alfabank.ru",
	"cbr.ru", "open.ru", "raiffeisen.ru", "gazprombank.ru", "psbank.ru", "rshb.ru", "sovcombank.ru",
	// Государственные ресурсы
	"gosuslugi.ru", "mos.ru", "nalog.gov.ru", "pfr.gov.ru", "kremlin.ru", "customs.gov.ru", "sfr.gov.ru",
	// Маркетплейсы и Ритейл
	"ozon.ru", "wildberries.ru", "wb.ru", "avito.ru", "market.yandex.ru", "megamarket.ru", "dns-shop.ru",
	"citilink.ru", "mvideo.ru", "eldorado.ru", "lamoda.ru", "sbermarket.ru", "vprok.ru", "magnit.ru", "5ka.ru",
	// Телеком и Операторы
	"mts.ru", "megafon.ru", "beeline.ru", "tele2.ru", "rt.ru", "rostelecom.ru", "yota.ru", "ttk.ru",
	// Поиск работы, ИТ и медиа
	"hh.ru", "superjob.ru", "rabota.ru", "habr.com", "3dnews.ru", "rutube.ru", "rbc.ru", "ria.ru", "lenta.ru",
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

	rawConfigs := make(chan string, 1000000)
	var wg sync.WaitGroup

	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          10000,
		MaxIdleConnsPerHost:   1000,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		DisableKeepAlives:     false,
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
	fmt.Printf("Собрано %d валидных уникальных прокси-ссылок.\n", totalConfigs)
	fmt.Println("=== [3/5] Запуск фильтрации низкого пинга (50-70мс) и валидации ТСПУ ===")

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
				fmt.Printf("Проверено узлов: %d / %d\r", curr, totalConfigs)
			}
		}(cfg)
	}

	testWg.Wait()
	close(resultsChan)
	fmt.Println("\nТестирование всех узлов полностью завершено.")

	var validResults []ConfigResult
	for res := range resultsChan {
		if res.Score > 0 {
			validResults = append(validResults, res)
		}
	}

	fmt.Printf("=== [4/5] Балансировка подписки (КВОТА RU SNI / REALITY ~85%%) (Валидных: %d) ===\n", len(validResults))

	var ruSNIConfigs []ConfigResult
	var realityConfigs []ConfigResult
	var noSNIConfigs []ConfigResult
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

	fmt.Printf("Доступно низколатентных узлов: [RU SNI: %d] | [REALITY: %d] | [No-SNI: %d] | [Прочие: %d]\n",
		len(ruSNIConfigs), len(realityConfigs), len(noSNIConfigs), len(otherConfigs))

	var selected []ConfigResult
	usedMap := make(map[string]bool)

	addUnique := func(item ConfigResult) bool {
		if len(selected) >= maxOutputLimit {
			return false
		}
		if !usedMap[item.URL] {
			selected = append(selected, item)
			usedMap[item.URL] = true
			return true
		}
		return false
	}

	// 1. Формирование приоритетного пула для белых списков РФ (RU SNI + REALITY)
	ruTargetQuota := (maxOutputLimit * 85) / 100

	for i := 0; i < len(ruSNIConfigs) && len(selected) < ruTargetQuota; i++ {
		addUnique(ruSNIConfigs[i])
	}

	for i := 0; i < len(realityConfigs) && len(selected) < ruTargetQuota; i++ {
		addUnique(realityConfigs[i])
	}

	// 2. Заполнение оставшихся мест No-SNI и качественными резервами
	for _, res := range noSNIConfigs {
		addUnique(res)
	}
	for _, res := range ruSNIConfigs {
		addUnique(res)
	}
	for _, res := range realityConfigs {
		addUnique(res)
	}
	for _, res := range otherConfigs {
		addUnique(res)
	}

	var finalSlice []string
	for i, r := range selected {
		// Пометка типа конфига для удобства в клиенте
		tag := "RU-Bypass"
		if r.IsReality {
			tag = "REALITY-Fast"
		} else if r.IsRuSNI {
			tag = "WhiteSNI-Fast"
		}
		renamedURL := setConfigName(r.URL, fmt.Sprintf("MiGiTi-%s-%d", tag, i+1))
		finalSlice = append(finalSlice, renamedURL)
	}

	fmt.Printf("Сформирована итоговая подписка из %d прокси-конфигураций.\n", len(finalSlice))

	fmt.Println("=== [5/5] Запись выходных файлов подписок ===")
	rawOutput := strings.Join(finalSlice, "\n")
	_ = os.WriteFile("output_raw.txt", []byte(rawOutput), 0644)

	b64Output := base64.StdEncoding.EncodeToString([]byte(rawOutput))
	_ = os.WriteFile("output_base64.txt", []byte(b64Output), 0644)

	fmt.Printf("Процесс успешно завершен за %v! Файлы ready.\n", time.Since(startTime))
}

func testConfig(configStr string) (ConfigResult, bool) {
	host, port, sni, _, transport, proto := parseConfigDetails(configStr)
	if host == "" || port == "" {
		return ConfigResult{}, false
	}

	lowerCfg := strings.ToLower(configStr)

	// Отсекаем устаревшие протоколы, легко блокируемые ТСПУ на мобильных операторах
	if proto == "ssr" {
		return ConfigResult{}, false
	}

	if StrictPortsOnly && port != "443" && port != "80" && port != "8443" && port != "2053" && port != "2083" && port != "2087" && port != "2096" {
		return ConfigResult{}, false
	}

	if StrictVLESSOnly && proto != "vless" {
		return ConfigResult{}, false
	}

	if StrictRuSNIOnly && !isRuSNI(sni) {
		return ConfigResult{}, false
	}

	// 1. Предварительная проверка совместимости с белыми списками
	if !simulateTSPUBypassCheck(proto, port, sni, lowerCfg) {
		return ConfigResult{}, false
	}

	start := time.Now()

	// 2. Проверка через Xray Core
	passedServices, mandatoryPassed := checkTargetServicesViaProxy(configStr)
	if !mandatoryPassed {
		return ConfigResult{}, false
	}

	latency := time.Since(start)

	// Отбрасываем узлы с высоким пингом из Runner, чтобы на мобильной симке было не выше ~50-70мс
	if latency > maxAllowedRunnerLatency {
		return ConfigResult{}, false
	}

	isReality := strings.Contains(lowerCfg, "security=reality") || strings.Contains(lowerCfg, "pbk=")
	ruSNI := isRuSNI(sni)
	noSNI := isNoSNI(sni, host)
	score := calculateBypassScore(configStr, port, sni, transport, latency, passedServices)

	return ConfigResult{
		URL:            configStr,
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

func simulateTSPUBypassCheck(proto, port, sni, lowerCfg string) bool {
	ruSNI := isRuSNI(sni)
	isReality := strings.Contains(lowerCfg, "security=reality") || strings.Contains(lowerCfg, "pbk=")
	isTLS := strings.Contains(lowerCfg, "security=tls")

	// Разрешаем порты, проходящие фильтрацию
	validPorts := map[string]bool{
		"80": true, "443": true, "8080": true, "8443": true, "2053": true, "2083": true, "2087": true, "2096": true, "4433": true,
	}

	if !isTLS && !isReality && !validPorts[port] {
		return false
	}

	// Отсекаем открытый Shadowsocks без маскировки
	if (proto == "ss" || proto == "shadowsocks") && !ruSNI && !isReality && !validPorts[port] {
		return false
	}

	// Фильтрация заблокированных зарубежных SNI
	if isTLS && !isReality && !ruSNI {
		blockedSNIs := []string{
			"cloudflare.com", "cloudfront.net", "facebook.com", "instagram.com",
			"twitter.com", "netflix.com", "medium.com", "bbc.com", "discord.com",
		}
		for _, b := range blockedSNIs {
			if strings.Contains(sni, b) {
				return false
			}
		}
	}

	return true
}

func getFreeLocalPort() (int, error) {
	for i := 0; i < 30; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(25000))
		if err != nil {
			continue
		}
		port := int(n.Int64()) + 20000
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		l, err := net.Listen("tcp", addr)
		if err == nil {
			_ = l.Close()
			return port, nil
		}
	}
	return 0, fmt.Errorf("no free port found")
}

func checkTargetServicesViaProxy(configStr string) (int, bool) {
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

	ctx, cancel := context.WithTimeout(context.Background(), serviceTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, corePath, "run", "-c", "stdin:")
	cmd.Stdin = bytes.NewReader(xrayConfigJSON)

	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

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
		conn, err := net.DialTimeout("tcp", socksAddr, 20*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			proxyReady = true
			break
		}
		time.Sleep(10 * time.Millisecond)
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
		DisableKeepAlives: true,
	}
	defer httpTransport.CloseIdleConnections()

	client := &http.Client{
		Transport: httpTransport,
		Timeout:   3000 * time.Millisecond,
	}

	var wg sync.WaitGroup
	var successCount int64

	mandatoryPassedMap := make(map[string]bool)
	var mapMutex sync.Mutex
	for _, name := range mandatoryServiceNames {
		mandatoryPassedMap[name] = false
	}

	for _, service := range targetServices {
		wg.Add(1)
		go func(s TargetService) {
			defer wg.Done()

			reqCtx, reqCancel := context.WithTimeout(ctx, 2800*time.Millisecond)
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
				mapMutex.Lock()
				if _, exists := mandatoryPassedMap[s.Name]; exists {
					mandatoryPassedMap[s.Name] = true
				}
				mapMutex.Unlock()
			}
		}(service)
	}

	wg.Wait()

	mapMutex.Lock()
	allMandatoryPassed := true
	for _, name := range mandatoryServiceNames {
		if !mandatoryPassedMap[name] {
			allMandatoryPassed = false
			break
		}
	}
	mapMutex.Unlock()

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

	var query url.Values
	var uuid string

	u, err := url.Parse(configURL)
	if err == nil && u != nil {
		query = u.Query()
		if u.User != nil {
			uuid = u.User.Username()
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

	if netType == "" {
		netType = "tcp"
	}

	streamSettings := map[string]interface{}{
		"network":  netType,
		"security": security,
		"sockopt": map[string]interface{}{
			"mark": 255,
		},
	}

	if security == "reality" {
		streamSettings["realitySettings"] = map[string]interface{}{
			"serverName":  sni,
			"fingerprint": fp,
			"publicKey":   pbk,
			"shortId":     sid,
			"spiderX":     "/",
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
				{
					"address":  host,
					"port":     port,
					"password": uuid,
				},
			},
		}
	case "vmess":
		outboundSettings = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": host,
					"port":    port,
					"users": []map[string]interface{}{
						{
							"id":       uuid,
							"alterId":  0,
							"security": "auto",
						},
					},
				},
			},
		}
	case "shadowsocks", "ss":
		outboundProtocol = "shadowsocks"
		method := "aes-128-gcm"
		password := uuid
		if strings.Contains(uuid, ":") {
			parts := strings.SplitN(uuid, ":", 2)
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
	default: // vless
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

	fmt.Println("Бинарник Xray Core не найден. Загрузка последнего релиза...")

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
		fmt.Println("Предупреждение: Автозагрузка Xray недоступна для этой платформы.")
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
	if err != nil {
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

	scanner := bufio.NewScanner(strings.Reader(content))
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
		strings.HasPrefix(lower, "hysteria2://") ||
		strings.HasPrefix(lower, "hy2://") ||
		strings.HasPrefix(lower, "tuic://")
}

func calculateBypassScore(configStr string, port string, sni string, transport string, latency time.Duration, passedServices int) int {
	score := 100 + (passedServices * 100)
	lower := strings.ToLower(configStr)

	// Высокий приоритет белым рос. SNI (проходят любые ТСПУ белые списки)
	if isRuSNI(sni) {
		score += 500
	}

	// REALITY дает максимальную устойчивость на мобильном трафике
	if strings.Contains(lower, "security=reality") || strings.Contains(lower, "pbk=") {
		score += 450
	}

	// gRPC работает лучше и стабильнее при частой смене IP/вышек мобильного оператора
	if transport == "grpc" {
		score += 120
	} else if transport == "tcp" {
		score += 80
	}

	// Высокий штраф за пинг, чтобы отсеять все медленные конфигурации
	pingMs := int(latency.Milliseconds())
	score -= pingMs * 5

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

func isNoSNI(sni string, host string) bool {
	if sni == "" {
		return true
	}
	if net.ParseIP(sni) != nil || net.ParseIP(host) != nil {
		return true
	}
	return false
}

func setConfigName(configURL string, name string) string {
	safeName := strings.ReplaceAll(name, " ", "-")
	if idx := strings.Index(configURL, "#"); idx != -1 {
		return configURL[:idx] + "#" + safeName
	}
	return configURL + "#" + safeName
}

func parseConfigDetails(configStr string) (host string, port string, sni string, path string, transport string, proto string) {
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
					port = fmt.Sprintf("%v", p)
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

	if strings.HasPrefix(configStr, "ss://") {
		raw := configStr[5:]
		if idx := strings.Index(raw, "#"); idx != -1 {
			raw = raw[:idx]
		}

		if strings.Contains(raw, "@") {
			parts := strings.SplitN(raw, "@", 2)
			userInfo := parts[0]
			hostPort := parts[1]

			if !strings.Contains(userInfo, ":") {
				if decoded, err := decodeBase64Flex(userInfo); err == nil {
					userInfo = string(decoded)
				}
			}

			if hpHost, hpPort, err := net.SplitHostPort(hostPort); err == nil {
				return hpHost, hpPort, "", "/", "tcp", "ss"
			}
		} else {
			if decoded, err := decodeBase64Flex(raw); err == nil {
				decodedStr := string(decoded)
				if strings.Contains(decodedStr, "@") {
					parts := strings.SplitN(decodedStr, "@", 2)
					if hpHost, hpPort, err := net.SplitHostPort(parts[1]); err == nil {
						return hpHost, hpPort, "", "/", "tcp", "ss"
					}
				}
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
		case "ss", "ssr":
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
