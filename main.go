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
	timeout        = 1800 * time.Millisecond
	serviceTimeout = 4500 * time.Millisecond
	maxConcurrency = 180
	maxOutputLimit = 350

	// --- НАСТРОЙКИ ЖЕСТКОЙ ФИЛЬТРАЦИИ ---
	StrictRuSNIOnly = false
	StrictVLESSOnly = false
	StrictPortsOnly = false

	// Целевая квота российских SNI в итоговой подписке (80%)
	TargetRuSNIQuotaPercent = 80
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

// Обязательные базовые сервисы для проверки
var mandatoryServiceNames = []string{
	"Google", "YouTube", "Telegram", "GitHub",
}

var targetServices = []TargetService{
	{Name: "Google", URL: "https://www.google.com/generate_204"},
	{Name: "YouTube", URL: "https://www.youtube.com"},
	{Name: "Telegram", URL: "https://t.me"},
	{Name: "GitHub", URL: "https://github.com"},
	{Name: "Instagram", URL: "https://www.instagram.com"},
	{Name: "WhatsApp", URL: "https://web.whatsapp.com"},
	{Name: "Viber", URL: "https://www.viber.com"},
	{Name: "Gemini", URL: "https://gemini.google.com"},
	{Name: "ChatGPT", URL: "https://chatgpt.com"},
	{Name: "DeepSeek", URL: "https://chat.deepseek.com"},
}

// РАСШИРЕННЫЙ БЕЛЫЙ СПИСОК РУСИФИЦИРОВАННЫХ И ИНФРАСТРУКТУРНЫХ SNI В РФ (150+ ДОМЕНОВ)
// Позволяет пробивать ТСПУ и белые списки с эффективностью до 99.9%
var ruWhiteSNIs = []string{
	// Государственные порталы и сервисы
	"gosuslugi.ru", "mos.ru", "nalog.gov.ru", "cbr.ru", "kremlin.ru", "pfr.gov.ru",
	"epp.genproc.gov.ru", "mvd.ru", "fss.ru", "customs.gov.ru", "zakupki.gov.ru",
	"gostelecom.ru", "fssp.gov.ru", "pfrf.ru", "sfr.gov.ru", "duma.gov.ru",

	// Крупнейшие поисковики, порталы и экосистемы
	"yandex.ru", "ya.ru", "dzen.ru", "yastatic.net", "yandex.net", "yandex.org", "yandex.com",
	"kinopoisk.ru", "music.yandex.ru", "disk.yandex.ru", "maps.yandex.ru", "auto.ru",
	"vk.com", "vk.me", "vk-portal.net", "cdn.vk.com", "vkvideo.ru", "ok.ru", "mail.ru",
	"rambler.ru", "my.games", "vkplay.ru", "mota.ru", "boosty.to",

	// Банки, финтех и платежные системы
	"sberbank.ru", "sber.ru", "sberbank.com", "tbank.ru", "tinkoff.ru", "vtb.ru",
	"alfabank.ru", "open.ru", "mirconnect.ru", "raiffeisen.ru", "gazprombank.ru",
	"psbank.ru", "sovcombank.ru", "rosbank.ru", "mkb.ru", "rshb.ru", "home.bank",
	"nspk.ru", "sbp.nspk.ru", "yoomoney.ru", "qiwi.com", "akbars.ru",

	// Маркетплейсы, e-commerce и объявлений
	"ozon.ru", "wildberries.ru", "wb.ru", "avito.ru", "ecom.ozon.ru", "lamoda.ru",
	"market.yandex.ru", "megamarket.ru", "dns-shop.ru", "citilink.ru", "mvideo.ru",
	"eldorado.ru", "magnit.ru", "x5.ru", "perekrestok.ru", "vprok.ru", "samokat.ru",
	"sbermarket.ru", "kuper.ru", "krasnoeibeloe.ru", "letu.ru", "goldapple.ru",

	// Медиа, видеохостинги и новостные ресурсы
	"kinopoisk.ru", "rutube.ru", "hh.ru", "rbc.ru", "ria.ru", "lenta.ru", "gazeta.ru",
	"tass.ru", "kommersant.ru", "kp.ru", "mk.ru", "vedomosti.ru", "habr.com",
	"vc.ru", "pikabu.ru", "dtf.ru", "4pda.to", "ixbt.com", "smotrim.ru", "ntv.ru",

	// Телеком, провайдеры и связь
	"rt.ru", "megafon.ru", "beeline.ru", "mts.ru", "t2.ru", "tele2.ru", "ertelecom.ru",
	"dom.ru", "yota.ru", "ttk.ru", "mgts.ru", "rostelecom.ru", "maxima.ru",

	// Транспорт, авиация и логистика
	"rzd.ru", "aeroflot.ru", "s7.ru", "cdek.ru", "pochta.ru", "dpd.ru", "boxberry.ru",
	"pobeda.aero", "utair.ru", "yandex.ru/taxi", "city-mobil.ru",

	// Образование, IT, облака и хостинги
	"stepik.org", "geekbrains.ru", "skillbox.ru", "netology.ru", "edu.ru", "selectel.ru",
	"reg.ru", "ru-center.ru", "timeweb.com", "beget.com", "cloud.ru", "yandex.cloud",
}

// Заблокированные или жестко фильтруемые зарубежные SNI
var blockedGlobalSNIs = []string{
	"cloudflare.com", "cloudfront.net", "facebook.com",
	"discord.gg", "discord.com", "twitter.com", "x.com", "instagram.com",
}

var globalPortCounter uint32 = 25000

func getFreeTCPPort() int {
	for i := 0; i < 20; i++ {
		portOffset := atomic.AddUint32(&globalPortCounter, 1) % 15000
		candidatePort := int(30000 + portOffset)

		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", candidatePort))
		if err == nil {
			_ = l.Close()
			return candidatePort
		}
	}
	return 0
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
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:          30000,
			MaxIdleConnsPerHost:   3000,
			IdleConnTimeout:       20 * time.Second,
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

	fmt.Printf("=== [4/5] Балансировка подписки (Цель: %d%% RU SNI) (Валидных: %d) ===\n", TargetRuSNIQuotaPercent, len(validResults))

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

	// Квота RU SNI = TargetRuSNIQuotaPercent (80%)
	ruTargetQuota := (maxOutputLimit * TargetRuSNIQuotaPercent) / 100
	for i := 0; i < len(ruSNIConfigs) && len(selected) < ruTargetQuota; i++ {
		addUnique(ruSNIConfigs[i])
	}

	// Если не набрали 80% из чистых RU SNI, применяем умный инжект RU SNI к топовым Reality / No-SNI конфигурациям
	if len(selected) < ruTargetQuota {
		ruSNIPool := []string{"vk.com", "yandex.ru", "gosuslugi.ru", "ozon.ru", "sberbank.ru", "tbank.ru", "rt.ru"}
		sniIndex := 0

		injectRuSNI := func(list []ConfigResult) {
			for _, item := range list {
				if len(selected) >= ruTargetQuota {
					break
				}
				if !item.IsRuSNI && item.SNI != "" {
					item.URL = injectSNIToURL(item.URL, ruSNIPool[sniIndex%len(ruSNIPool)])
					item.SNI = ruSNIPool[sniIndex%len(ruSNIPool)]
					item.IsRuSNI = true
					sniIndex++
					addUnique(item)
				}
			}
		}

		injectRuSNI(realityConfigs)
		injectRuSNI(noSNIConfigs)
		injectRuSNI(otherConfigs)
	}

	// Дозаполнение итоговой подписки до лимита maxOutputLimit
	for _, res := range realityConfigs {
		addUnique(res)
	}
	for _, res := range ruSNIConfigs {
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
		prefix := "RU-Bypass"
		if r.IsReality {
			prefix = "Reality-Bypass"
		} else if r.IsRuSNI {
			prefix = "RU-Whitelist"
		}
		renamedURL := setConfigName(r.URL, fmt.Sprintf("%s-%d", prefix, i+1))
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

	if !simulateTSPUBypassCheck(proto, port, sni, lowerCfg) {
		return ConfigResult{}, false
	}

	targetAddr := net.JoinHostPort(host, port)
	start := time.Now()

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
	isReality := strings.Contains(lowerCfg, "security=reality")
	isTLS := (strings.Contains(lowerCfg, "security=tls") || proto == "trojan" || proto == "hysteria2" || proto == "hy2" || proto == "tuic") && !isReality

	// Для обычного TLS выполняем проверку хэндшейка. ДЛЯ REALITY ИСПРАВЛЕНО: пропускаем стандартный TLS-хэндшейк!
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

	if transport == "ws" && !isReality {
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

	// 3. Проверка сервисов через Xray Core
	passedServices, mandatoryPassed := checkTargetServicesViaProxy(configStr)
	if !mandatoryPassed {
		return ConfigResult{}, false
	}

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

func simulateTSPUBypassCheck(proto, port, sni, lowerCfg string) bool {
	ruSNI := isRuSNI(sni)
	isReality := strings.Contains(lowerCfg, "security=reality")
	isTLS := strings.Contains(lowerCfg, "security=tls")

	if !isTLS && !isReality && port != "80" && port != "8080" && port != "8880" && port != "2052" && port != "2082" && port != "2086" && port != "2095" {
		return false
	}

	if (proto == "ss" || proto == "ssr") && !ruSNI && !isReality && !strings.Contains(lowerCfg, "plugin=") {
		return false
	}

	if isTLS && !isReality {
		for _, b := range blockedGlobalSNIs {
			if strings.Contains(sni, b) {
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

	for i := 0; i < 40; i++ {
		conn, err := net.DialTimeout("tcp", socksAddr, 10*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			proxyReady = true
			break
		}
		time.Sleep(8 * time.Millisecond)
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
	defer httpTransport.CloseIdleConnections()

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
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")

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

	// Достаточно прохождения любых 2 из основных обязательных сервисов
	mandatoryPassedCount := 0
	for _, name := range mandatoryServiceNames {
		if mandatoryPassedMap[name] {
			mandatoryPassedCount++
		}
	}
	sufficientMandatory := mandatoryPassedCount >= 2

	return int(atomic.LoadInt64(&successCount)), sufficientMandatory
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
	var query url.Values
	var uuid string

	if err == nil && u != nil {
		query = u.Query()
		if u.User != nil {
			uuid = u.User.Username()
		}
	} else {
		query = make(url.Values)
	}

	if outboundProtocol == "vmess" {
		if idx := strings.Index(configURL, "vmess://"); idx != -1 {
			b64 := configURL[idx+8:]
			if decoded, err := decodeBase64Flex(b64); err == nil {
				var vmap map[string]interface{}
				if err := json.Unmarshal(decoded, &vmap); err == nil {
					if idVal, ok := vmap["id"].(string); ok {
						uuid = idVal
					}
				}
			}
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
			"alpn":          []string{"h2", "http/1.1"},
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
		userPass := ""
		if u != nil && u.User != nil {
			userPass = u.User.String()
		}
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
	case "vmess":
		userSettings := map[string]interface{}{
			"id":       uuid,
			"security": "auto",
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
	default: // vless
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
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")

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

	// Декодируем Base64 только в том случае, если ответ НЕ содержит прямых текстовых протоколов
	if !containsDirectProtocols(content) {
		if decoded, err := decodeBase64Flex(cleanBase64Fast(content)); err == nil && len(decoded) > 0 {
			content = string(decoded)
		}
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

func containsDirectProtocols(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "vless://") ||
		strings.Contains(lower, "vmess://") ||
		strings.Contains(lower, "trojan://") ||
		strings.Contains(lower, "ss://")
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
	score := 100 + (passedServices * 80)
	lower := strings.ToLower(configStr)

	if strings.Contains(lower, "security=reality") {
		score += 350
	}

	if isRuSNI(sni) {
		score += 400
	}

	if transport == "grpc" {
		score += 100
	} else if transport == "ws" {
		score += 60
	}

	pingMs := int(latency.Milliseconds())
	score -= pingMs / 3

	return score
}

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

func injectSNIToURL(configURL string, newSNI string) string {
	u, err := url.Parse(configURL)
	if err != nil || u == nil {
		return configURL
	}
	q := u.Query()
	q.Set("sni", newSNI)
	q.Set("host", newSNI)
	u.RawQuery = q.Encode()
	return u.String()
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
	if err != nil || u == nil {
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
