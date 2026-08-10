package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
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
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	tcpDialTimeout  = 1200 * time.Millisecond
	serviceTimeout  = 3800 * time.Millisecond
	maxConcurrency  = 180
	maxOutputLimit  = 350
	ruTargetPercent = 80 // 80% долей конфигураций с российскими SNI

	// --- НАСТРОЙКИ ФИЛЬТРАЦИИ ---
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
	Host           string
	Port           string
	IsRuSNI        bool
	IsNoSNI        bool
	IsReality      bool
	CountryTag     string
}

type TargetService struct {
	Name     string
	URL      string
	Critical bool
	Weight   int
}

var targetServices = []TargetService{
	{Name: "Google", URL: "https://www.google.com/generate_204", Critical: true, Weight: 15},
	{Name: "Telegram", URL: "https://t.me", Critical: true, Weight: 20},
	{Name: "GitHub", URL: "https://github.com", Critical: true, Weight: 15},
	{Name: "YouTube", URL: "https://www.youtube.com", Critical: false, Weight: 10},
	{Name: "Instagram", URL: "https://www.instagram.com", Critical: false, Weight: 10},
	{Name: "WhatsApp", URL: "https://web.whatsapp.com", Critical: false, Weight: 10},
	{Name: "Viber", URL: "https://www.viber.com", Critical: false, Weight: 5},
	{Name: "Gemini", URL: "https://gemini.google.com", Critical: false, Weight: 5},
	{Name: "ChatGPT", URL: "https://chatgpt.com", Critical: false, Weight: 5},
	{Name: "DeepSeek", URL: "https://chat.deepseek.com", Critical: false, Weight: 5},
}

// РАСШИРЕННЫЙ БЕЛЫЙ СПИСОК SNI И ИНФРАСТРУКТУРНЫХ ДОМЕНОВ РФ (200+ ДОМЕНОВ)
var ruWhiteSNIs = []string{
	// Государственные ресурсы и инфраструктура
	"gosuslugi.ru", "gu-st.ru", "mos.ru", "nalog.gov.ru", "cbr.ru", "kremlin.ru", "pfr.gov.ru", "epp.genproc.gov.ru",
	"customs.gov.ru", "nalog.ru", "sfr.gov.ru", "mvd.ru", "fssp.gov.ru", "rosreestr.gov.ru", "rostelecom.ru",
	"pfrf.ru", "fss.ru", "gosuslugi29.ru", "uslugi27.ru", "pgu.mos.ru", "zakupki.gov.ru", "pravo.gov.ru",

	// Крупнейшие экосистемы, поисковики и порталы
	"yandex.ru", "ya.ru", "dzen.ru", "yastatic.net", "yandex.net", "yandex.org", "yandex.com", "kinopoisk.ru",
	"vk.com", "vk.me", "vk-portal.net", "cdn.vk.com", "userapi.com", "ok.ru", "mail.ru", "rambler.ru",
	"my.games", "vkplay.ru", "vk.ru", "sber.ru", "tbank.ru", "tinkoff.ru", "rustore.ru",

	// Банки и финансовый сектор
	"sberbank.ru", "sberbank.com", "vtb.ru", "alfabank.ru", "open.ru", "mirconnect.ru", "raiffeisen.ru",
	"gazprombank.ru", "psbank.ru", "sovcombank.ru", "rshb.ru", "rosbank.ru", "postbank.ru", "unicredit-bank.ru",
	"mkb.ru", "home.bank", "domrfbank.ru", "pochtabank.ru", "mtsbank.ru", "ubrr.ru", "akbars.ru",

	// Маркетплейсы, сервисы объявлений и ритейл
	"ozon.ru", "ozon.st", "ecom.ozon.ru", "wildberries.ru", "wb.ru", "wbstatic.net", "avito.ru", "avito.st",
	"lamoda.ru", "market.yandex.ru", "megamarket.ru", "sbermegamarket.ru", "dns-shop.ru", "mvideo.ru",
	"eldorado.ru", "citilink.ru", "vseinstrumenti.ru", "magnit.ru", "x5.ru", "perekrestok.ru", "5ka.ru",

	// Медиа, видеохостинги, пресса и работа
	"rutube.ru", "hh.ru", "rbc.ru", "ria.ru", "lenta.ru", "gazeta.ru", "kp.ru", "kommersant.ru",
	"tass.ru", "iz.ru", "vedomosti.ru", "interfax.ru", "smotrim.ru", "ivi.ru", "wink.ru", "okko.tv",
	"kino.pub", "dtf.ru", "habr.com", "pikabu.ru", "vc.ru",

	// Транспорт, авиация и доставка
	"rzd.ru", "aeroflot.ru", "s7.ru", "pobeda.aero", "utair.ru", "cdek.ru", "pochta.ru", "boxberry.ru",
	"yandex.by", "yandex.kz", "drom.ru", "auto.ru", "tutu.ru", "yandex.io",

	// Операторы связи и провайдеры
	"rt.ru", "megafon.ru", "beeline.ru", "mts.ru", "nornickel.ru", "maxima.ru", "t2.ru", "tele2.ru",
	"yota.ru", "ertelecom.ru", "dom.ru", "akado.ru", "tattelecom.ru", "ttk.ru",
}

// Заблокированные или жестко фильтруемые ТСПУ зарубежные SNI
var blockedGlobalSNIs = []string{
	"cloudflare.com", "cloudfront.net", "facebook.com", "fbcdn.net",
	"discord.gg", "discord.com", "twitter.com", "x.com", "instagram.com",
}

// Атомарный безопасный менеджер портов
type PortAllocator struct {
	current uint32
	mu      sync.Mutex
}

func NewPortAllocator(startPort uint32) *PortAllocator {
	return &PortAllocator{current: startPort}
}

func (pa *PortAllocator) GetFreePort() int {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	for i := 0; i < 500; i++ {
		port := atomic.AddUint32(&pa.current, 1)
		if port > 62000 {
			atomic.StoreUint32(&pa.current, 12000)
			port = 12000
		}

		addr := fmt.Sprintf("127.0.0.1:%d", port)
		l, err := net.Listen("tcp", addr)
		if err == nil {
			_ = l.Close()
			return int(port)
		}
	}
	return int(15000 + rand.Intn(20000))
}

var globalPortAllocator = NewPortAllocator(12000)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	startTime := time.Now()

	fmt.Println("=========================================================================")
	fmt.Println("===   HIGH-SPEED PROXY SUB-AGGREGATOR & TSPU/DPI BYPASS ENGINE v3.5   ===")
	fmt.Println("=========================================================================")

	fmt.Println("=== [1/5] Инициализация окружения и поиск бинарников Xray Core ===")
	ensureCoreAvailable()

	sources, err := readLines("sources.txt")
	if err != nil {
		fmt.Printf("Ошибка чтения sources.txt: %v. Создаем пустые выходные файлы.\n", err)
		writeEmptyOutputs()
		return
	}

	fmt.Printf("Загружено источников подписок: %d\n", len(sources))
	fmt.Println("=== [2/5] Высокоскоростной асинхронный сбор и декодирование ссылок ===")

	rawConfigs := make(chan string, 100000)
	var fetchWg sync.WaitGroup

	sharedHTTPClient := &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:          10000,
			MaxIdleConnsPerHost:   1000,
			IdleConnTimeout:       10 * time.Second,
			ResponseHeaderTimeout: 4 * time.Second,
			DisableKeepAlives:     false,
		},
	}

	for _, src := range sources {
		src = strings.TrimSpace(src)
		if src == "" || strings.HasPrefix(src, "#") {
			continue
		}
		fetchWg.Add(1)
		go func(targetURL string) {
			defer fetchWg.Done()
			fetchSubscriptionWithClient(sharedHTTPClient, targetURL, rawConfigs)
		}(src)
	}

	go func() {
		fetchWg.Wait()
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
	fmt.Printf("Собрано %d уникальных прокси-конфигураций.\n", totalConfigs)
	fmt.Println("=== [3/5] Двухуровневый экспресс-тест (TCP/TLS + Xray Core + SNI Mutation) ===")

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

			if res, ok := testConfigWithMutation(c); ok {
				resultsChan <- res
			}

			curr := atomic.AddInt64(&processedCount, 1)
			if curr%1000 == 0 || curr == int64(totalConfigs) {
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

	fmt.Printf("=== [4/5] Балансировка подписки (Цель: >= %d%% RU SNI) (Валидных: %d) ===\n", ruTargetPercent, len(validResults))

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

	// 1. Квота RU SNI = 80% (например 280 из 350)
	ruTargetQuota := (maxOutputLimit * ruTargetPercent) / 100
	for i := 0; i < len(ruSNIConfigs) && len(selected) < ruTargetQuota; i++ {
		addUnique(ruSNIConfigs[i])
	}

	// 2. Заполнение REALITY (как наиболее стойких)
	for _, res := range realityConfigs {
		addUnique(res)
	}

	// 3. Дозаполнение оставшимися RU SNI узлами
	for _, res := range ruSNIConfigs {
		addUnique(res)
	}

	// 4. Дозаполнение No-SNI и остальными прокси
	for _, res := range noSNIConfigs {
		addUnique(res)
	}
	for _, res := range otherConfigs {
		addUnique(res)
	}

	var finalSlice []string
	var ruOnlySlice []string

	for i, r := range selected {
		nodeTag := fmt.Sprintf("🇷🇺 RU-Bypass-%03d | %s | %dms", i+1, strings.ToUpper(r.Protocol), r.Latency.Milliseconds())
		if !r.IsRuSNI && r.IsReality {
			nodeTag = fmt.Sprintf("⚡ REALITY-Bypass-%03d | %dms", i+1, r.Latency.Milliseconds())
		} else if !r.IsRuSNI {
			nodeTag = fmt.Sprintf("🌐 Global-Bypass-%03d | %s | %dms", i+1, strings.ToUpper(r.Protocol), r.Latency.Milliseconds())
		}

		renamedURL := setConfigName(r.URL, nodeTag)
		finalSlice = append(finalSlice, renamedURL)

		if r.IsRuSNI {
			ruOnlySlice = append(ruOnlySlice, renamedURL)
		}
	}

	fmt.Printf("Сформирован итоговый МИКС из %d прокси-конфигураций (Из них RU SNI: %d).\n", len(finalSlice), len(ruOnlySlice))

	fmt.Println("=== [5/5] Запись всех выходных файлов подписок ===")
	rawOutput := strings.Join(finalSlice, "\n")
	_ = os.WriteFile("output_raw.txt", []byte(rawOutput), 0644)

	b64Output := base64.StdEncoding.EncodeToString([]byte(rawOutput))
	_ = os.WriteFile("output_base64.txt", []byte(b64Output), 0644)

	// Дополнительный 100% RU-SNI файл подписки для жестких белых списков
	ruRawOutput := strings.Join(ruOnlySlice, "\n")
	_ = os.WriteFile("output_ru_only.txt", []byte(ruRawOutput), 0644)

	// Экспорт статистических данных в JSON
	generateStatsJSON(selected, totalConfigs, time.Since(startTime))

	// Экспорт конфигураций Sing-Box и Clash
	generateSingBoxConfig(selected)
	generateClashConfig(selected)

	fmt.Printf("Процесс успешно завершен за %v! Все файлы созданы.\n", time.Since(startTime))
}

// Тестирование конфигурации с автоматической подменой/мутацией SNI
func testConfigWithMutation(configStr string) (ConfigResult, bool) {
	// 1. Сначала пробуем оригинальный конфиг
	if res, ok := testConfig(configStr); ok {
		return res, true
	}

	// 2. Если не прошел, но это TLS/VLESS/VMess/Trojan с заблокированным или отсутствующим SNI - делаем мутацию SNI
	host, port, sni, path, transport, proto := parseConfigDetails(configStr)
	if host == "" || port == "" {
		return ConfigResult{}, false
	}

	lowerCfg := strings.ToLower(configStr)
	isTLS := strings.Contains(lowerCfg, "security=tls") || proto == "trojan"

	if isTLS && (!isRuSNI(sni) || isBlockedSNI(sni)) {
		// Подставляем один из топ-4 проверенных российских SNI
		mutatedSNIs := []string{"ya.ru", "vk.com", "gosuslugi.ru", "ozon.ru"}
		for _, mutSNI := range mutatedSNIs {
			mutatedCfg := replaceSNInURL(configStr, mutSNI)
			if res, ok := testConfig(mutatedCfg); ok {
				return res, true
			}
		}
	}

	return ConfigResult{}, false
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

	// 1. Фильтрация ТСПУ
	if !simulateTSPUBypassCheck(proto, port, sni, lowerCfg) {
		return ConfigResult{}, false
	}

	targetAddr := net.JoinHostPort(host, port)
	start := time.Now()

	// 2. Уровень 1: Экспресс-проверка TCP/TLS
	dialer := &net.Dialer{Timeout: tcpDialTimeout}
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
		_ = tlsConn.SetDeadline(time.Now().Add(tcpDialTimeout))

		if err := tlsConn.Handshake(); err != nil {
			_ = rawConn.Close()
			return ConfigResult{}, false
		}
		conn = tlsConn
	}

	if transport == "ws" {
		wsReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", path, serverName)
		_ = conn.SetDeadline(time.Now().Add(tcpDialTimeout))
		_, err := conn.Write([]byte(wsReq))
		if err != nil {
			_ = conn.Close()
			return ConfigResult{}, false
		}

		buf := make([]byte, 256)
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

	// 3. Уровень 2: Проверка реальной доступности сервисов через Xray Core
	passedServices, isOperational := checkTargetServicesViaProxy(configStr)
	if !isOperational {
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
		Host:           host,
		Port:           port,
		IsRuSNI:        ruSNI,
		IsNoSNI:        noSNI,
		IsReality:      isReality,
	}, true
}

func simulateTSPUBypassCheck(proto, port, sni, lowerCfg string) bool {
	ruSNI := isRuSNI(sni)
	isReality := strings.Contains(lowerCfg, "security=reality")
	isTLS := strings.Contains(lowerCfg, "security=tls")

	// Отсекаем заблокированные глобальные SNI
	if isBlockedSNI(sni) && !ruSNI {
		return false
	}

	// Незашифрованные протоколы на нестандартных портах мгновенно блокируются ТСПУ
	if !isTLS && !isReality && port != "80" && port != "8080" && port != "8880" && port != "2052" && port != "2082" {
		return false
	}

	// Блокировка сырого Shadowsocks без плагинов и TLS
	if (proto == "ss" || proto == "ssr") && !ruSNI && !isReality && !strings.Contains(lowerCfg, "plugin=") {
		return false
	}

	return true
}

func checkTargetServicesViaProxy(configStr string) (int, bool) {
	corePath := findCoreExecutable()
	if corePath == "" {
		return 0, false
	}

	socksPort := globalPortAllocator.GetFreePort()

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

	for i := 0; i < 25; i++ {
		conn, err := net.DialTimeout("tcp", socksAddr, 12*time.Millisecond)
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
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: 10,
	}

	client := &http.Client{
		Transport: httpTransport,
		Timeout:   serviceTimeout - (400 * time.Millisecond),
	}

	var wg sync.WaitGroup
	var totalWeight int64
	var successCount int64
	var criticalPassed int64

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
				atomic.AddInt64(&totalWeight, int64(s.Weight))
				if s.Critical {
					atomic.AddInt64(&criticalPassed, 1)
				}
			}
		}(service)
	}

	wg.Wait()

	passed := atomic.LoadInt64(&successCount)
	crit := atomic.LoadInt64(&criticalPassed)

	// Узел считается валидным, если прошли хотя бы 2 критических сервиса ИЛИ набрано >= 25 баллов
	isOperational := crit >= 2 || atomic.LoadInt64(&totalWeight) >= 25 || passed >= 3
	return int(passed), isOperational
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

	security := "none"
	uuid := ""
	pbk := ""
	sid := ""
	fp := "chrome"
	flow := ""

	if strings.HasPrefix(configURL, "vmess://") {
		b64 := configURL[8:]
		if idx := strings.Index(b64, "#"); idx != -1 {
			b64 = b64[:idx]
		}
		decoded, err := decodeBase64Flex(b64)
		if err == nil {
			var vmap map[string]interface{}
			if err := json.Unmarshal(decoded, &vmap); err == nil {
				if id, ok := vmap["id"].(string); ok {
					uuid = id
				}
				if tlsVal, ok := vmap["tls"].(string); ok && (tlsVal == "tls" || tlsVal == "1") {
					security = "tls"
				}
			}
		}
	} else {
		u, err := url.Parse(configURL)
		if err == nil {
			query := u.Query()
			uuid = u.User.Username()
			security = query.Get("security")
			pbk = query.Get("pbk")
			if pbk == "" {
				pbk = query.Get("public-key")
			}
			sid = query.Get("sid")
			if sid == "" {
				sid = query.Get("short-id")
			}
			if f := query.Get("fp"); f != "" {
				fp = f
			}
			flow = query.Get("flow")
		}
	}

	if security == "" {
		if outboundProtocol == "trojan" || outboundProtocol == "hysteria2" || outboundProtocol == "hy2" || outboundProtocol == "tuic" {
			security = "tls"
		} else {
			security = "none"
		}
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
		u, _ := url.Parse(configURL)
		sName := ""
		if u != nil {
			sName = u.Query().Get("serviceName")
		}
		streamSettings["grpcSettings"] = map[string]interface{}{
			"serviceName": sName,
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
	case "shadowsocks":
		userPass := ""
		u, err := url.Parse(configURL)
		if err == nil {
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
				{"address": host, "port": port, "method": method, "password": password},
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
		fmt.Println("Найден локальный бинарник Xray Core / Sing-Box.")
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 20*1024*1024))
	if err != nil {
		return
	}

	content := string(body)
	if decoded, err := decodeBase64Flex(cleanBase64Fast(content)); err == nil && len(decoded) > 0 {
		content = string(decoded)
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)

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
	score := 100 + (passedServices * 90)
	lower := strings.ToLower(configStr)

	if isRuSNI(sni) {
		score += 450 // Максимальный бонус за российский SNI для прохождения ТСПУ
	}

	if strings.Contains(lower, "security=reality") {
		score += 350
	}

	if transport == "grpc" {
		score += 120
	} else if transport == "ws" {
		score += 80
	}

	if port == "443" || port == "8443" || port == "2053" || port == "2083" {
		score += 100
	}

	pingMs := int(latency.Milliseconds())
	score -= pingMs / 2

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

func isBlockedSNI(sni string) bool {
	if sni == "" {
		return false
	}
	sniLower := strings.ToLower(strings.TrimSpace(sni))
	for _, b := range blockedGlobalSNIs {
		if sniLower == b || strings.HasSuffix(sniLower, "."+b) {
			return true
		}
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

func replaceSNInURL(configURL string, newSNI string) string {
	if strings.Contains(configURL, "sni=") {
		re := regexp.MustCompile(`sni=[^&^#]+`)
		return re.ReplaceAllString(configURL, "sni="+newSNI)
	}
	if strings.Contains(configURL, "?") {
		idx := strings.Index(configURL, "?")
		return configURL[:idx+1] + "sni=" + newSNI + "&" + configURL[idx+1:]
	}
	if idx := strings.Index(configURL, "#"); idx != -1 {
		return configURL[:idx] + "?sni=" + newSNI + configURL[idx:]
	}
	return configURL + "?sni=" + newSNI
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

func writeEmptyOutputs() {
	_ = os.WriteFile("output_raw.txt", []byte(""), 0644)
	_ = os.WriteFile("output_base64.txt", []byte(""), 0644)
	_ = os.WriteFile("output_ru_only.txt", []byte(""), 0644)
}

func generateStatsJSON(results []ConfigResult, totalParsed int, elapsed time.Duration) {
	ruCount := 0
	realityCount := 0
	for _, r := range results {
		if r.IsRuSNI {
			ruCount++
		}
		if r.IsReality {
			realityCount++
		}
	}

	stats := map[string]interface{}{
		"updated_at":      time.Now().Format(time.RFC3339),
		"elapsed_time":    elapsed.String(),
		"total_parsed":    totalParsed,
		"valid_selected":  len(results),
		"ru_sni_count":    ruCount,
		"ru_sni_percent":  fmt.Sprintf("%.1f%%", float64(ruCount)/float64(len(results))*100),
		"reality_count":   realityCount,
		"target_services": len(targetServices),
	}

	data, err := json.MarshalIndent(stats, "", "  ")
	if err == nil {
		_ = os.WriteFile("output_stats.json", data, 0644)
	}
}

func generateSingBoxConfig(results []ConfigResult) {
	outbounds := []map[string]interface{}{
		{
			"type": "selector",
			"tag":  "SELECT",
			"outbounds": []string{
				"AUTO-BEST",
			},
		},
	}

	var autoOutbounds []string
	for i, r := range results {
		tag := fmt.Sprintf("Node-%03d-RU", i+1)
		autoOutbounds = append(autoOutbounds, tag)

		portInt, _ := strconv.Atoi(r.Port)
		outbound := map[string]interface{}{
			"type":        r.Protocol,
			"tag":         tag,
			"server":      r.Host,
			"server_port": portInt,
		}
		outbounds = append(outbounds, outbound)
	}

	outbounds[0]["outbounds"] = append(outbounds[0]["outbounds"].([]string), autoOutbounds...)

	config := map[string]interface{}{
		"outbounds": outbounds,
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err == nil {
		_ = os.WriteFile("output_singbox.json", data, 0644)
	}
}

func generateClashConfig(results []ConfigResult) {
	var sb strings.Builder
	sb.WriteString("port: 7890\nsocks-port: 7891\nallow-lan: true\nmode: rule\nlog-level: info\n\nproxies:\n")

	for i, r := range results {
		sb.WriteString(fmt.Sprintf("  - name: \"RU-Bypass-%03d\"\n", i+1))
		sb.WriteString(fmt.Sprintf("    type: %s\n", r.Protocol))
		sb.WriteString(fmt.Sprintf("    server: %s\n", r.Host))
		sb.WriteString(fmt.Sprintf("    port: %s\n", r.Port))
		if r.SNI != "" {
			sb.WriteString(fmt.Sprintf("    sni: %s\n", r.SNI))
		}
		sb.WriteString("    udp: true\n")
	}

	_ = os.WriteFile("output_clash.yaml", []byte(sb.String()), 0644)
}
