package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"container/heap"
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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// === КОНФИГУРАЦИОННЫЕ КОНСТАНТЫ (Подстроены под GitHub Actions Runner: 2 vCPU, 7GB RAM) ===
const (
	maxOutputLimit        = 300
	workerConcurrency     = 16               // Оптимальное количество воркеров под 2 CPU
	fetchConcurrency      = 8                // Параллельное скачивание источников
	tcpTimeout            = 800 * time.Millisecond
	serviceTimeout        = 2500 * time.Millisecond
	dnsTTL                = 15 * time.Minute
	geoCacheMaxEntries    = 5000
	maxSubscriptionMemory = 8 * 1024 * 1024  // Ограничение размера 1 подписки: 8MB
)

// Mетрики работы программы
type ExecutionMetrics struct {
	SourcesCount      int64
	FetchedConfigs    int64
	UniqueConfigs     int64
	Stage1Passed      int64
	TCPPassed         int64
	ProxyTested       int64
	ValidResults      int64
	DNSCacheHits      int64
	GeoIPCacheHits    int64
}

var metrics ExecutionMetrics

// Структура результата
type ConfigResult struct {
	URL            string
	Latency        time.Duration
	Score          int
	ServiceSuccess int
	SNI            string
	Protocol       string
	CountryCode    string
	IsNearRU       bool
	IsRuSNI        bool
	HasBypassTech  bool
}

// Bounded Priority Queue (Min-Heap для сохранения Top-N лучших результатов без полной сортировки)
type PriorityQueue []*ConfigResult

func (pq PriorityQueue) Len() int           { return len(pq) }
func (pq PriorityQueue) Less(i, j int) bool {
	if pq[i].ServiceSuccess == pq[j].ServiceSuccess {
		if pq[i].Score == pq[j].Score {
			return pq[i].Latency > pq[j].Latency // Храним наихудший сверху для быстрого выталкивания
		}
		return pq[i].Score < pq[j].Score
	}
	return pq[i].ServiceSuccess < pq[j].ServiceSuccess
}
func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}
func (pq *PriorityQueue) Push(x interface{}) {
	*pq = append(*pq, x.(*ConfigResult))
}
func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	*pq = old[0 : n-1]
	return item
}

type SafeTopNHeap struct {
	mu sync.Mutex
	pq PriorityQueue
}

func NewSafeTopNHeap(capacity int) *SafeTopNHeap {
	h := &SafeTopNHeap{pq: make(PriorityQueue, 0, capacity)}
	heap.Init(&h.pq)
	return h
}

func (h *SafeTopNHeap) Push(res *ConfigResult) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.pq.Len() < maxOutputLimit {
		heap.Push(&h.pq, res)
	} else if h.isBetter(res, h.pq[0]) {
		heap.Pop(&h.pq)
		heap.Push(&h.pq, res)
	}
}

func (h *SafeTopNHeap) isBetter(a, b *ConfigResult) bool {
	if a.ServiceSuccess != b.ServiceSuccess {
		return a.ServiceSuccess > b.ServiceSuccess
	}
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	return a.Latency < b.Latency
}

func (h *SafeTopNHeap) ToSortedSlice() []ConfigResult {
	h.mu.Lock()
	defer h.mu.Unlock()

	size := h.pq.Len()
	result := make([]ConfigResult, size)
	for i := size - 1; i >= 0; i-- {
		result[i] = *(heap.Pop(&h.pq).(*ConfigResult))
	}
	return result
}

// Target Services
type TargetService struct {
	Name           string
	URL            string
	ExpectedStatus func(code int) bool
}

var targetServices = []TargetService{
	{
		Name:           "Google",
		URL:            "https://www.google.com/generate_204",
		ExpectedStatus: func(c int) bool { return c == 204 || c == 200 },
	},
	{
		Name:           "Telegram",
		URL:            "https://t.me",
		ExpectedStatus: func(c int) bool { return c == 200 || c == 302 },
	},
	{
		Name:           "GitHub",
		URL:            "https://github.com",
		ExpectedStatus: func(c int) bool { return c == 200 },
	},
	{
		Name:           "YouTube",
		URL:            "https://www.youtube.com",
		ExpectedStatus: func(c int) bool { return c == 200 },
	},
	{
		Name:           "Instagram",
		URL:            "https://www.instagram.com",
		ExpectedStatus: func(c int) bool { return c == 200 || c == 301 || c == 302 },
	},
	{
		Name:           "WhatsApp",
		URL:            "https://web.whatsapp.com",
		ExpectedStatus: func(c int) bool { return c == 200 || c == 302 },
	},
	{
		Name:           "ChatGPT",
		URL:            "https://chatgpt.com",
		ExpectedStatus: func(c int) bool { return c == 200 || c == 307 || c == 403 },
	},
}

var ruWhiteSNIs = []string{
	"ya.ru", "yandex.ru", "yandex.com", "api-maps.yandex.ru", "avatars.mds.yandex.net",
	"browser.yandex.ru", "dzen.ru", "kinopoisk.ru", "hd.kinopoisk.ru", "st.kinopoisk.ru",
	"mail.yandex.ru", "mc.yandex.ru", "strm.yandex.ru", "travel.yandex.ru",
	"vk.com", "vk.ru", "m.vk.com", "api.vk.ru", "id.vk.ru", "userapi.com",
	"mail.ru", "e.mail.ru", "cloud.mail.ru", "avito.ru", "ozon.ru", "wb.ru", "wildberries.ru",
	"sberbank.ru", "tbank.ru", "alfabank.ru", "vtb.ru", "gosuslugi.ru", "mos.ru",
	"2gis.ru", "rutube.ru", "rambler.ru", "rbc.ru", "mts.ru", "megafon.ru", "beeline.ru",
}

var nearRUCountries = map[string]bool{
	"RU": true, "BY": true, "KZ": true, "AM": true, "GE": true,
	"FI": true, "SE": true, "EE": true, "LV": true, "LT": true,
	"PL": true, "DE": true, "NL": true, "MD": true, "UA": true,
	"UZ": true, "AZ": true, "KG": true, "TJ": true, "TR": true, "AT": true,
}

// Cache structures with TTL
type dnsCacheEntry struct {
	ip        string
	expiresAt time.Time
}

type FastDNSCache struct {
	mu    sync.RWMutex
	items map[string]dnsCacheEntry
}

var dnsCache = &FastDNSCache{items: make(map[string]dnsCacheEntry)}

func (d *FastDNSCache) Get(host string) (string, bool) {
	d.mu.RLock()
	entry, ok := d.items[host]
	d.mu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		atomic.AddInt64(&metrics.DNSCacheHits, 1)
		return entry.ip, true
	}
	return "", false
}

func (d *FastDNSCache) Set(host, ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.items[host] = dnsCacheEntry{
		ip:        ip,
		expiresAt: time.Now().Add(dnsTTL),
	}
}

type SimpleGeoCache struct {
	mu    sync.RWMutex
	items map[string]string
}

var geoCache = &SimpleGeoCache{items: make(map[string]string)}

func (c *SimpleGeoCache) Get(key string) (string, bool) {
	c.mu.RLock()
	val, ok := c.items[key]
	c.mu.RUnlock()
	if ok {
		atomic.AddInt64(&metrics.GeoIPCacheHits, 1)
	}
	return val, ok
}

func (c *SimpleGeoCache) Set(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) >= geoCacheMaxEntries {
		// Очистка 20% старых записей вместо половинного сброса
		count := 0
		for k := range c.items {
			delete(c.items, k)
			count++
			if count >= geoCacheMaxEntries/5 {
				break
			}
		}
	}
	c.items[key] = value
}

var globalResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 1200 * time.Millisecond}
		conn, err := d.DialContext(ctx, "udp", "1.1.1.1:53")
		if err != nil {
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		}
		return conn, nil
	},
}

// === MAIN ENTRYPOINT ===
func main() {
	startTime := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Println("=== [1/5] Инициализация среды и ядра sing-box ===")
	if err := ensureCoreAvailable(ctx); err != nil {
		fmt.Printf("Ошибка подготовки sing-box core: %v\n", err)
	}

	sources, err := readLines("sources.txt")
	if err != nil || len(sources) == 0 {
		fmt.Printf("Внимание: sources.txt не найден или пуст: %v. Создаем пустые выходы.\n", err)
		_ = safeWriteFile("output_raw.txt", []byte(""))
		_ = safeWriteFile("output_base64.txt", []byte(""))
		return
	}
	atomic.StoreInt64(&metrics.SourcesCount, int64(len(sources)))
	fmt.Printf("Успешно загружено источников: %d\n", len(sources))

	fmt.Println("=== [2/5] Сбор, потоковая фильтрация и Base64 декодирование ===")
	
	rawConfigs := make(chan string, 2000)
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       20 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		DisableKeepAlives:     false,
	}

	sharedHTTPClient := &http.Client{
		Timeout:   12 * time.Second,
		Transport: tr,
	}

	var fetchWg sync.WaitGroup
	fetchSem := make(chan struct{}, fetchConcurrency)

	for _, src := range sources {
		src = strings.TrimSpace(src)
		if src == "" || strings.HasPrefix(src, "#") || strings.HasPrefix(src, "//") {
			continue
		}
		fetchWg.Add(1)
		go func(targetURL string) {
			defer fetchWg.Done()
			fetchSem <- struct{}{}
			defer func() { <-fetchSem }()
			fetchSubscriptionWithClient(ctx, sharedHTTPClient, targetURL, rawConfigs)
		}(src)
	}

	go func() {
		fetchWg.Wait()
		close(rawConfigs)
		tr.CloseIdleConnections()
	}()

	uniqueConfigs := make(map[string]struct{})
	for cfg := range rawConfigs {
		cfg = sanitizeProxyURL(cfg)
		if cfg != "" && len(cfg) < 4096 && isProxyProtocol(cfg) {
			uniqueConfigs[cfg] = struct{}{}
		}
	}

	totalConfigs := len(uniqueConfigs)
	atomic.StoreInt64(&metrics.UniqueConfigs, int64(totalConfigs))
	fmt.Printf("Валидных уникальных прокси-ссылок в базе: %d\n", totalConfigs)

	if totalConfigs == 0 {
		fmt.Println("Нет валидных конфигураций для тестирования. Завершение работы.")
		_ = safeWriteFile("output_raw.txt", []byte(""))
		_ = safeWriteFile("output_base64.txt", []byte(""))
		return
	}

	fmt.Println("=== [3/5] Оптимизированный аудит ТСПУ + Многоэтапное тестирование ===")

	topHeap := NewSafeTopNHeap(maxOutputLimit)
	configChan := make(chan string, 1000)

	go func() {
		for cfg := range uniqueConfigs {
			configChan <- cfg
		}
		close(configChan)
	}()

	var testWg sync.WaitGroup
	var processedCount int64

	for i := 0; i < workerConcurrency; i++ {
		testWg.Add(1)
		go func() {
			defer testWg.Done()
			for cfg := range configChan {
				if res, ok := testConfig(ctx, cfg); ok {
					topHeap.Push(&res)
					atomic.AddInt64(&metrics.ValidResults, 1)
				}
				curr := atomic.AddInt64(&processedCount, 1)
				if curr%250 == 0 || curr == int64(totalConfigs) {
					fmt.Printf("Обработано конфигураций: %d / %d\r", curr, totalConfigs)
				}
			}
		}()
	}

	testWg.Wait()
	fmt.Println("\nТестирование полностью завершено.")

	selected := topHeap.ToSortedSlice()
	fmt.Printf("=== [4/5] Ранжирование и формирование подписки (Отобрано Top-%d) ===\n", len(selected))

	var finalSlice []string
	for i, r := range selected {
		displayName := fmt.Sprintf("MiGiTi #%d | TG: MiGiTi_official_channel", i+1)
		renamedURL := setConfigNameUniversal(r.URL, displayName)
		finalSlice = append(finalSlice, renamedURL)
	}

	serverCount := len(finalSlice)
	fmt.Printf("Сформировано конфигов в итоговой подписке: %d шт.\n", serverCount)

	fmt.Println("=== [5/5] Запись результативных файлов ===")

	mskLoc := time.FixedZone("MSK", 3*3600)
	updateTimeStr := time.Now().In(mskLoc).Format("2006-01-02 15:04:05")

	subscriptionHeader := fmt.Sprintf("//profile-title: MIGITI Subscriptions\n"+
		"//profile-update-interval: 1\n"+
		"//subscription-userinfo: upload=0; download=0; total=1073741824000; expire=0\n"+
		"//total-nodes: %d\n"+
		"//updated-at: %s MSK\n"+
		"//channel: https://t.me/MiGiTi_official_channel\n"+
		"//chat: https://t.me/MiGiTi_official_chat\n"+
		"//forum: https://t.me/MiGiTi_FORUM\n"+
		"//site: https://misha12333211-ctrl.github.io/MiGiTi/\n"+
		"//profile-web-page-url: https://github.com/misha12333211-ctrl/proxy-subs\n\n",
		serverCount, updateTimeStr)

	rawOutput := subscriptionHeader + strings.Join(finalSlice, "\n")
	if err := safeWriteFile("output_raw.txt", []byte(rawOutput)); err != nil {
		fmt.Printf("Ошибка записи output_raw.txt: %v\n", err)
	}

	b64Output := base64.StdEncoding.EncodeToString([]byte(rawOutput))
	if err := safeWriteFile("output_base64.txt", []byte(b64Output)); err != nil {
		fmt.Printf("Ошибка записи output_base64.txt: %v\n", err)
	}

	fmt.Println("\n=== Сводка выполнения / Metrics ===")
	fmt.Printf("Источников: %d | Конфигов получено: %d | Уникальных: %d\n", metrics.SourcesCount, metrics.FetchedConfigs, metrics.UniqueConfigs)
	fmt.Printf("Stage 1 (Фильтр) пройдено: %d | TCP Ping пройдено: %d | Proxy проверено: %d\n", metrics.Stage1Passed, metrics.TCPPassed, metrics.ProxyTested)
	fmt.Printf("DNS Cache Hits: %d | GeoIP Cache Hits: %d\n", metrics.DNSCacheHits, metrics.GeoIPCacheHits)
	fmt.Printf("Итоговое время выполнения: %v!\n", time.Since(startTime))
}

func safeWriteFile(filename string, data []byte) error {
	tmpFile := filename + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpFile, filename)
}

// === MULTI-STAGE PIPELINE (Многоэтапное тестирование) ===
func testConfig(ctx context.Context, configStr string) (ConfigResult, bool) {
	// STAGE 1: Быстрая синтаксическая валидация
	host, port, sni, transport, proto, security, flow := parseConfigDetails(configStr)
	if host == "" || port == "" {
		return ConfigResult{}, false
	}

	if !passTSPUBypassFilter(proto, port, sni, security, configStr) {
		return ConfigResult{}, false
	}
	atomic.AddInt64(&metrics.Stage1Passed, 1)

	// STAGE 2: Быстрый TCP Ping без тяжелых процессов
	realPing, resolvedIP, ok := measureTCPPingWithDNS(ctx, host, port)
	if !ok || realPing > tcpTimeout {
		return ConfigResult{}, false
	}
	atomic.AddInt64(&metrics.TCPPassed, 1)

	// STAGE 3: Комплексная проверка через sing-box
	atomic.AddInt64(&metrics.ProxyTested, 1)
	passedServices, ok := checkTargetServicesViaProxy(ctx, configStr)
	if !ok || passedServices < 1 {
		return ConfigResult{}, false
	}

	// STAGE 4: Определение геолокации и скоринг
	ruSNI := isRuSNI(sni)
	hasBypassTech := security == "reality" || proto == "hysteria2" || proto == "hy2" || proto == "tuic" || flow != "" || strings.Contains(configStr, "fp=")

	countryCode := getIPCountryCode(ctx, resolvedIP)
	isNearRU := nearRUCountries[countryCode]

	score := calculateBypassScore(configStr, port, sni, transport, realPing, passedServices, isNearRU, countryCode, ruSNI, hasBypassTech)

	return ConfigResult{
		URL:            configStr,
		Latency:        realPing,
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

func passTSPUBypassFilter(proto, port, sni, security, fullURL string) bool {
	if (proto == "ss" || proto == "ssr") && security == "none" && !strings.Contains(fullURL, "plugin=") {
		return false
	}
	if (proto == "vless" || proto == "vmess") && (security == "none" || security == "") {
		return false
	}
	if proto == "vless" || proto == "vmess" || proto == "trojan" {
		if security != "reality" && security != "tls" {
			return false
		}
	}
	return true
}

func measureTCPPingWithDNS(ctx context.Context, host string, port string) (time.Duration, string, bool) {
	ipStr := host
	if net.ParseIP(host) == nil {
		if cachedIP, found := dnsCache.Get(host); found {
			ipStr = cachedIP
		} else {
			reqCtx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
			ips, err := globalResolver.LookupHost(reqCtx, host)
			cancel()
			if err != nil || len(ips) == 0 {
				return 0, "", false
			}
			ipStr = ips[0]
			dnsCache.Set(host, ipStr)
		}
	}

	address := net.JoinHostPort(ipStr, port)
	start := time.Now()

	d := net.Dialer{Timeout: tcpTimeout}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return 0, "", false
	}
	_ = conn.Close()
	return time.Since(start), ipStr, true
}

func checkTargetServicesViaProxy(parentCtx context.Context, configStr string) (int, bool) {
	corePath := findCoreExecutable()
	if corePath == "" {
		return 0, false
	}

	socksPort, err := getFreePortNumber()
	if err != nil {
		return 0, false
	}

	singBoxConfigJSON, err := generateSingBoxConfig(configStr, socksPort)
	if err != nil {
		return 0, false
	}

	tmpConfigFile, err := os.CreateTemp("", "sb_cfg_*.json")
	if err != nil {
		return 0, false
	}
	tmpConfigPath := tmpConfigFile.Name()
	_, _ = tmpConfigFile.Write(singBoxConfigJSON)
	_ = tmpConfigFile.Close()

	defer os.Remove(tmpConfigPath)

	ctx, cancel := context.WithTimeout(parentCtx, serviceTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, corePath, "run", "-c", tmpConfigPath)

	if err := cmd.Start(); err != nil {
		return 0, false
	}

	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	proxyReady := false
	for i := 0; i < 25; i++ {
		conn, err := net.DialTimeout("tcp", socksAddr, 20*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			proxyReady = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}

	if !proxyReady {
		return 0, false
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
	httpTransport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 1200 * time.Millisecond,
		ForceAttemptHTTP2:   false,
	}
	defer httpTransport.CloseIdleConnections()

	client := &http.Client{
		Transport: httpTransport,
		Timeout:   1500 * time.Millisecond,
	}

	// Ранний выход (Early Exit Stage): сначала проверяем только Google (быстрая планка качества)
	fastReq, err := http.NewRequestWithContext(ctx, "GET", targetServices[0].URL, nil)
	if err != nil {
		return 0, false
	}
	fastReq.Header.Set("User-Agent", "Mozilla/5.0 Chrome/128.0.0.0")
	resp, err := client.Do(fastReq)
	if err != nil || !targetServices[0].ExpectedStatus(resp.StatusCode) {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return 0, false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()

	// Если базовый узел прошел Stage 1, проверяем остальной набор параллельно
	var wg sync.WaitGroup
	var successCount int64 = 1 // Google уже успешен

	for _, service := range targetServices[1:] {
		wg.Add(1)
		go func(s TargetService) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, "GET", s.URL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/128.0.0.0")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()

			if s.ExpectedStatus(resp.StatusCode) {
				atomic.AddInt64(&successCount, 1)
			}
		}(service)
	}

	wg.Wait()
	totalSuccess := int(atomic.LoadInt64(&successCount))
	return totalSuccess, true
}

func getFreePortNumber() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port, nil
}

func generateSingBoxConfig(configURL string, socksPort int) ([]byte, error) {
	host, portStr, sni, path, netType, outboundProtocol, security, flow := parseConfigDetails(configURL)
	if host == "" {
		return nil, fmt.Errorf("invalid host")
	}

	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}

	if sni == "" {
		sni = host
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
	if fp == "" && (security == "tls" || security == "reality") {
		fp = "chrome"
	}

	if security == "reality" && pbk == "" {
		return nil, fmt.Errorf("reality missing public key")
	}

	outbound := map[string]interface{}{
		"server":      host,
		"server_port": port,
		"tag":         "proxy",
	}

	tlsConfig := map[string]interface{}{
		"enabled":     security == "tls" || security == "reality",
		"server_name": sni,
		"insecure":    true,
	}

	if fp != "" && (security == "tls" || security == "reality") {
		tlsConfig["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": fp,
		}
	}

	if security == "reality" {
		tlsConfig["reality"] = map[string]interface{}{
			"enabled":    true,
			"public_key": pbk,
			"short_id":   sid,
		}
	}

	var transportConfig map[string]interface{}
	if netType == "ws" {
		headers := map[string]interface{}{}
		if sni != "" {
			headers["Host"] = sni
		}
		transportConfig = map[string]interface{}{
			"type":    "ws",
			"path":    path,
			"headers": headers,
		}
	} else if netType == "grpc" {
		serviceName := query.Get("serviceName")
		if serviceName == "" {
			serviceName = query.Get("path")
		}
		transportConfig = map[string]interface{}{
			"type":         "grpc",
			"service_name": serviceName,
		}
	}

	switch outboundProtocol {
	case "vless":
		outbound["type"] = "vless"
		outbound["uuid"] = uuid
		if flow != "" {
			outbound["flow"] = flow
		}
		if security == "tls" || security == "reality" {
			outbound["tls"] = tlsConfig
		}
		if transportConfig != nil {
			outbound["transport"] = transportConfig
		}

	case "vmess":
		outbound["type"] = "vmess"
		outbound["uuid"] = uuid
		outbound["security"] = "auto"
		if security == "tls" || security == "reality" {
			outbound["tls"] = tlsConfig
		}
		if transportConfig != nil {
			outbound["transport"] = transportConfig
		}

	case "trojan":
		outbound["type"] = "trojan"
		outbound["password"] = uuid
		if security == "tls" || security == "reality" {
			outbound["tls"] = tlsConfig
		}
		if transportConfig != nil {
			outbound["transport"] = transportConfig
		}

	case "shadowsocks", "ss":
		outbound["type"] = "shadowsocks"
		method := "aes-256-gcm"
		password := uuid
		if strings.Contains(uuid, ":") {
			parts := strings.SplitN(uuid, ":", 2)
			method = parts[0]
			password = parts[1]
		}
		outbound["method"] = method
		outbound["password"] = password

	case "hysteria2", "hy2":
		outbound["type"] = "hysteria2"
		outbound["password"] = uuid
		outbound["tls"] = tlsConfig
		if obfs := query.Get("obfs"); obfs != "" {
			outbound["obfs"] = map[string]interface{}{
				"type":     obfs,
				"password": query.Get("obfs-password"),
			}
		}

	case "tuic":
		outbound["type"] = "tuic"
		outbound["uuid"] = uuid
		if pass := query.Get("password"); pass != "" {
			outbound["password"] = pass
		}
		outbound["tls"] = tlsConfig
		outbound["congestion_control"] = "bbr"

	default:
		outbound["type"] = "vless"
		outbound["uuid"] = uuid
		if security == "tls" || security == "reality" {
			outbound["tls"] = tlsConfig
		}
	}

	config := map[string]interface{}{
		"log": map[string]interface{}{"level": "panic"},
		"inbounds": []map[string]interface{}{
			{
				"type":        "socks",
				"tag":         "socks-in",
				"listen":      "127.0.0.1",
				"listen_port": socksPort,
			},
		},
		"outbounds": []map[string]interface{}{outbound},
	}

	return json.Marshal(config)
}

func findCoreExecutable() string {
	if path, err := exec.LookPath("sing-box"); err == nil {
		return path
	}
	cwd, err := os.Getwd()
	if err == nil {
		exe := "sing-box"
		if runtime.GOOS == "windows" {
			exe = "sing-box.exe"
		}
		local := filepath.Join(cwd, exe)
		if _, err := os.Stat(local); err == nil {
			return local
		}
	}
	return ""
}

func ensureCoreAvailable(ctx context.Context) error {
	if findCoreExecutable() != "" {
		return nil
	}

	fmt.Println("Автоматическая установка sing-box Core...")
	var downloadURL string
	version := "1.8.11"

	switch runtime.GOOS {
	case "linux":
		if runtime.GOARCH == "amd64" {
			downloadURL = fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-amd64.tar.gz", version, version)
		} else if runtime.GOARCH == "arm64" {
			downloadURL = fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-arm64.tar.gz", version, version)
		}
	case "windows":
		downloadURL = fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-windows-amd64.zip", version, version)
	}

	if downloadURL == "" {
		return fmt.Errorf("unsupported OS/arch: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return fmt.Errorf("download failed: %v", err)
	}
	defer resp.Body.Close()

	cwd, _ := os.Getwd()
	targetExe := "sing-box"
	if runtime.GOOS == "windows" {
		targetExe = "sing-box.exe"
	}

	outPath := filepath.Join(cwd, targetExe)

	if strings.HasSuffix(downloadURL, ".zip") {
		tmpZip, err := os.CreateTemp("", "sb_download_*.zip")
		if err != nil {
			return err
		}
		defer os.Remove(tmpZip.Name())

		if _, err := io.Copy(tmpZip, resp.Body); err != nil {
			_ = tmpZip.Close()
			return err
		}
		_ = tmpZip.Close()

		r, err := zip.OpenReader(tmpZip.Name())
		if err != nil {
			return err
		}
		defer r.Close()

		for _, f := range r.File {
			cleanName := filepath.Base(filepath.Clean(f.Name))
			if cleanName == targetExe {
				rc, err := f.Open()
				if err != nil {
					return err
				}

				tmpOut, err := os.CreateTemp(cwd, "singbox_tmp_*")
				if err != nil {
					_ = rc.Close()
					return err
				}

				_, err = io.Copy(tmpOut, rc)
				_ = rc.Close()
				_ = tmpOut.Close()
				if err != nil {
					_ = os.Remove(tmpOut.Name())
					return err
				}

				_ = os.Chmod(tmpOut.Name(), 0755)
				if err := os.Rename(tmpOut.Name(), outPath); err != nil {
					_ = os.Remove(tmpOut.Name())
					return err
				}
				fmt.Printf("sing-box Core успешно развернут: (%s)\n", outPath)
				return nil
			}
		}
	} else if strings.HasSuffix(downloadURL, ".tar.gz") {
		gzr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return err
		}
		defer gzr.Close()

		tr := tar.NewReader(gzr)
		for {
			header, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			cleanName := filepath.Base(filepath.Clean(header.Name))
			if cleanName == targetExe {
				tmpOut, err := os.CreateTemp(cwd, "singbox_tmp_*")
				if err != nil {
					return err
				}

				if _, err := io.Copy(tmpOut, tr); err != nil {
					_ = tmpOut.Close()
					_ = os.Remove(tmpOut.Name())
					return err
				}
				_ = tmpOut.Close()

				_ = os.Chmod(tmpOut.Name(), 0755)
				if err := os.Rename(tmpOut.Name(), outPath); err != nil {
					_ = os.Remove(tmpOut.Name())
					return err
				}
				fmt.Printf("sing-box Core успешно развернут: (%s)\n", outPath)
				return nil
			}
		}
	}
	return fmt.Errorf("core binary not found in downloaded archive")
}

func fetchSubscriptionWithClient(ctx context.Context, client *http.Client, targetURL string, out chan<- string) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/128.0.0.0")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 256*1024))
			_ = resp.Body.Close()
		}
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 256*1024))
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSubscriptionMemory))
	if err != nil {
		return
	}
	decodeSubscriptionContent(string(body), out)
}

func decodeSubscriptionContent(content string, out chan<- string) {
	content = strings.TrimPrefix(content, "\xef\xbb\xbf")
	content = strings.TrimSpace(content)

	scanner := bufio.NewScanner(strings.NewReader(content))
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, maxSubscriptionMemory)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if isProxyProtocol(line) {
			atomic.AddInt64(&metrics.FetchedConfigs, 1)
			out <- line
			continue
		}

		cleaned := cleanBase64Fast(line)
		if len(cleaned) >= 16 {
			if decoded, err := decodeBase64Flex(cleaned); err == nil && len(decoded) > 0 {
				subScanner := bufio.NewScanner(bytes.NewReader(decoded))
				for subScanner.Scan() {
					subLine := strings.TrimSpace(subScanner.Text())
					if isProxyProtocol(subLine) {
						atomic.AddInt64(&metrics.FetchedConfigs, 1)
						out <- subLine
					}
				}
			}
		}
	}
}

func sanitizeProxyURL(u string) string {
	u = strings.TrimSpace(u)
	u = strings.ReplaceAll(u, "\r", "")
	u = strings.ReplaceAll(u, "\n", "")
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

func getIPCountryCode(ctx context.Context, ipStr string) string {
	if ipStr == "" {
		return ""
	}

	if val, ok := geoCache.Get(ipStr); ok {
		return val
	}

	reqCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", "https://freeipapi.com/api/json/"+ipStr, nil)
	if err != nil {
		return ""
	}

	client := &http.Client{Timeout: 800 * time.Millisecond}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var res struct {
		CountryCode string `json:"countryCode"`
	}
	if json.NewDecoder(resp.Body).Decode(&res) == nil && res.CountryCode != "" {
		geoCache.Set(ipStr, res.CountryCode)
		return res.CountryCode
	}
	return ""
}

// Скоринг без искусственного искажения latency
func calculateBypassScore(configStr string, port string, sni string, transport string, latency time.Duration, passedServices int, isNearRU bool, countryCode string, ruSNI bool, hasBypassTech bool) int {
	score := 100 + (passedServices * 500)

	if countryCode == "RU" {
		score += 2500
	} else if isNearRU {
		score += 1200
	}

	if ruSNI {
		score += 2000
	}
	if hasBypassTech {
		score += 1500
	}

	if transport == "grpc" {
		score += 300
	} else if transport == "ws" {
		score += 200
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

func setConfigNameUniversal(configURL string, name string) string {
	escapedName := url.PathEscape(name)
	escapedName = strings.ReplaceAll(escapedName, "#", "%23")

	if strings.HasPrefix(configURL, "vmess://") && len(configURL) > 8 {
		b64 := configURL[8:]
		if idx := strings.Index(b64, "#"); idx != -1 {
			b64 = b64[:idx]
		}
		decoded, err := decodeBase64Flex(b64)
		if err == nil {
			var vmap map[string]interface{}
			if err := json.Unmarshal(decoded, &vmap); err == nil && vmap != nil {
				vmap["ps"] = name
				if newJSON, err := json.Marshal(vmap); err == nil {
					return "vmess://" + base64.StdEncoding.EncodeToString(newJSON)
				}
			}
		}
	}

	if idx := strings.Index(configURL, "#"); idx != -1 {
		return configURL[:idx] + "#" + escapedName
	}
	return configURL + "#" + escapedName
}

func parseConfigDetails(configStr string) (host string, port string, sni string, transport string, proto string, security string, flow string) {
	if strings.HasPrefix(configStr, "ss://") && len(configStr) > 5 {
		u, err := url.Parse(configStr)
		if err == nil && u.Hostname() != "" {
			host = u.Hostname()
			port = u.Port()
			query := u.Query()
			sni = query.Get("sni")
			if sni == "" {
				sni = query.Get("plugin")
			}
			return host, port, sni, "", "ss", "none", ""
		}

		raw := configStr[5:]
		if idx := strings.Index(raw, "#"); idx != -1 {
			raw = raw[:idx]
		}
		if idx := strings.Index(raw, "@"); idx != -1 {
			hostPort := raw[idx+1:]
			if hpHost, hpPort, err := net.SplitHostPort(hostPort); err == nil {
				return hpHost, hpPort, "", "", "ss", "none", ""
			}
		} else {
			if decoded, err := decodeBase64Flex(raw); err == nil {
				decStr := string(decoded)
				if idx := strings.Index(decStr, "@"); idx != -1 {
					hostPort := decStr[idx+1:]
					if hpHost, hpPort, err := net.SplitHostPort(hostPort); err == nil {
						return hpHost, hpPort, "", "", "ss", "none", ""
					}
				}
			}
		}
	}

	if strings.HasPrefix(configStr, "vmess://") && len(configStr) > 8 {
		b64 := configStr[8:]
		if idx := strings.Index(b64, "#"); idx != -1 {
			b64 = b64[:idx]
		}
		decoded, err := decodeBase64Flex(b64)
		if err == nil {
			var vmap map[string]interface{}
			if err := json.Unmarshal(decoded, &vmap); err == nil && vmap != nil {
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
				transport, _ = vmap["net"].(string)
				security, _ = vmap["tls"].(string)
				return host, port, sni, strings.ToLower(transport), "vmess", security, ""
			}
		}
	}

	u, err := url.Parse(configStr)
	if err != nil {
		return "", "", "", "", "", "", ""
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
	return host, port, sni, transport, proto, security, flow
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
