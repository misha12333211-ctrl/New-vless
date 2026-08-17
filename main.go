package main

import (
	"archive/tar"
	"archive/zip"
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
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// === Настройки Производительности для GitHub Actions ===
var (
	numCPU           = runtime.NumCPU()
	preflightWorkers = numCPU * 64 // Легкие проверочные TCP/TLS горутины
	singboxWorkers   = numCPU * 8  // Тяжелые интеграционные проверочные горутины
	maxOutputLimit   = 300
	pingTimeout      = 800 * time.Millisecond
	serviceTimeout   = 3500 * time.Millisecond
	fetchConcurrency = 32
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
	Name           string
	URL            string
	ExpectedStatus func(code int) bool
}

var targetServices = []TargetService{
	{Name: "Google", URL: "https://www.google.com/generate_204", ExpectedStatus: func(c int) bool { return c == 204 || c == 200 }},
	{Name: "Telegram", URL: "https://t.me", ExpectedStatus: func(c int) bool { return c == 200 || c == 302 }},
	{Name: "GitHub", URL: "https://github.com", ExpectedStatus: func(c int) bool { return c == 200 }},
	{Name: "YouTube", URL: "https://www.youtube.com", ExpectedStatus: func(c int) bool { return c == 200 }},
	{Name: "Instagram", URL: "https://www.instagram.com", ExpectedStatus: func(c int) bool { return c == 200 || c == 301 || c == 302 }},
	{Name: "WhatsApp", URL: "https://web.whatsapp.com", ExpectedStatus: func(c int) bool { return c == 200 || c == 302 }},
	{Name: "ChatGPT", URL: "https://chatgpt.com", ExpectedStatus: func(c int) bool { return c == 200 || c == 307 || c == 403 }},
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

var (
	geoCache    sync.Map
	dnsResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 1000 * time.Millisecond}
			return d.DialContext(ctx, "udp", "77.88.8.8:53")
		},
	}
	sharedHTTPClient *http.Client
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          500,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 4 * time.Second,
		DisableKeepAlives:     false,
	}
	sharedHTTPClient = &http.Client{
		Timeout:   8 * time.Second,
		Transport: tr,
	}
}

func main() {
	startTime := time.Now()

	fmt.Println("=== [1/5] Инициализация ядра sing-box ===")
	ensureCoreAvailable()

	sources, err := readLines("sources.txt")
	if err != nil || len(sources) == 0 {
		fmt.Printf("Ошибка: sources.txt не найден или пуст: %v. Создаем пустые выходы.\n", err)
		_ = os.WriteFile("output_raw.txt", []byte(""), 0644)
		_ = os.WriteFile("output_base64.txt", []byte(""), 0644)
		return
	}
	fmt.Printf("Загружено источников: %d (Рабочие потоки: Pre-flight=%d, Sing-box=%d)\n", len(sources), preflightWorkers, singboxWorkers)

	fmt.Println("=== [2/5] Высокоскоростной сбор и декодирование подписок ===")
	rawConfigs := make(chan string, 500000)
	var wg sync.WaitGroup
	fetchSem := make(chan struct{}, fetchConcurrency)

	for _, src := range sources {
		src = strings.TrimSpace(src)
		if src == "" || strings.HasPrefix(src, "#") || strings.HasPrefix(src, "//") {
			continue
		}
		wg.Add(1)
		go func(targetURL string) {
			defer wg.Done()
			fetchSem <- struct{}{}
			defer func() { <-fetchSem }()
			fetchSubscriptionWithClient(sharedHTTPClient, targetURL, rawConfigs)
		}(src)
	}

	go func() {
		wg.Wait()
		close(rawConfigs)
	}()

	uniqueConfigs := make(map[string]struct{}, 100000)
	for cfg := range rawConfigs {
		cfg = sanitizeProxyURL(cfg)
		if cfg != "" && len(cfg) < 4096 && isProxyProtocol(cfg) {
			uniqueConfigs[cfg] = struct{}{}
		}
	}

	totalConfigs := len(uniqueConfigs)
	fmt.Printf("Валидных уникальных прокси в базе: %d\n", totalConfigs)

	if totalConfigs == 0 {
		fmt.Println("Нет валидных конфигураций. Завершение.")
		_ = os.WriteFile("output_raw.txt", []byte(""), 0644)
		_ = os.WriteFile("output_base64.txt", []byte(""), 0644)
		return
	}

	fmt.Println("=== [3/5] Двухфазное ультра-быстрое тестирование ТСПУ ===")

	// Фаза 3.1: Нативный Go TCP/TLS Pre-flight фильтр
	type preflightResult struct {
		url     string
		latency time.Duration
	}
	preflightPassed := make(chan preflightResult, totalConfigs)
	preflightSem := make(chan struct{}, preflightWorkers)
	var pfWg sync.WaitGroup
	var pfProcessed int64

	for cfg := range uniqueConfigs {
		pfWg.Add(1)
		go func(c string) {
			defer pfWg.Done()
			preflightSem <- struct{}{}
			defer func() { <-preflightSem }()

			if lat, ok := fastPreflightCheck(c); ok {
				preflightPassed <- preflightResult{url: c, latency: lat}
			}

			curr := atomic.AddInt64(&pfProcessed, 1)
			if curr%1000 == 0 || curr == int64(totalConfigs) {
				fmt.Printf("Pre-flight пройдено: %d / %d\r", curr, totalConfigs)
			}
		}(cfg)
	}

	pfWg.Wait()
	close(preflightPassed)
	fmt.Printf("\nPre-flight фильтрация завершена. Прошло проверку: %d прокси.\n", len(preflightPassed))

	// Фаза 3.2: Тестирование сервисов через sing-box
	resultsChan := make(chan ConfigResult, len(preflightPassed))
	sbSem := make(chan struct{}, singboxWorkers)
	var sbWg sync.WaitGroup
	var sbProcessed int64
	totalPreflightPassed := len(preflightPassed)

	for pf := range preflightPassed {
		sbWg.Add(1)
		go func(item preflightResult) {
			defer sbWg.Done()
			sbSem <- struct{}{}
			defer func() { <-sbSem }()

			if res, ok := testConfigFull(item.url, item.latency); ok {
				resultsChan <- res
			}

			curr := atomic.AddInt64(&sbProcessed, 1)
			if curr%50 == 0 || curr == int64(totalPreflightPassed) {
				fmt.Printf("Sing-box проверено: %d / %d\r", curr, totalPreflightPassed)
			}
		}(pf)
	}

	sbWg.Wait()
	close(resultsChan)
	fmt.Println("\nТестирование полностью завершено.")

	var validResults []ConfigResult
	for res := range resultsChan {
		if res.Score > 0 && res.ServiceSuccess >= 1 {
			validResults = append(validResults, res)
		}
	}

	fmt.Printf("=== [4/5] Ранжирование под РФ (Успешных: %d) ===\n", len(validResults))

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
	usedMap := make(map[string]bool, maxOutputLimit)

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
		displayName := fmt.Sprintf("By MiGiTi SNI #%d", i+1)
		renamedURL := setConfigNameUniversal(r.URL, displayName)
		finalSlice = append(finalSlice, renamedURL)
	}

	fmt.Printf("Итоговая подписка содержит: %d прокси.\n", len(finalSlice))

	fmt.Println("=== [5/5] Запись файлов результатов ===")
	subscriptionHeader := "//profile-title: Go Engine By MiGiTi\n"
	rawOutput := subscriptionHeader + strings.Join(finalSlice, "\n")
	_ = os.WriteFile("output_raw.txt", []byte(rawOutput), 0644)

	b64Output := base64.StdEncoding.EncodeToString([]byte(rawOutput))
	_ = os.WriteFile("output_base64.txt", []byte(b64Output), 0644)

	fmt.Printf("Вся обработка выполнена за %v!\n", time.Since(startTime))
}

func fastPreflightCheck(configStr string) (time.Duration, bool) {
	host, port, sni, _, _, proto, security, _ := parseConfigDetails(configStr)
	if host == "" || port == "" {
		return 0, false
	}

	if !passTSPUBypassFilter(proto, port, sni, security, configStr) {
		return 0, false
	}

	address := net.JoinHostPort(host, port)
	start := time.Now()
	
	dialer := &net.Dialer{Timeout: pingTimeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return 0, false
	}
	
	latency := time.Since(start)

	// TLS Handshake тест для TLS/Reality
	if security == "tls" || security == "reality" {
		_ = conn.SetDeadline(time.Now().Add(600 * time.Millisecond))
		serverName := sni
		if serverName == "" {
			serverName = host
		}
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         serverName,
		})
		if err := tlsConn.Handshake(); err != nil {
			_ = conn.Close()
			return 0, false
		}
		_ = tlsConn.Close()
	} else {
		_ = conn.Close()
	}

	return latency, true
}

func testConfigFull(configStr string, realPing time.Duration) (ConfigResult, bool) {
	host, port, sni, _, transport, proto, security, flow := parseConfigDetails(configStr)

	passedServices, ok := checkTargetServicesViaProxy(configStr)
	if !ok || passedServices < 1 {
		return ConfigResult{}, false
	}

	countryCode := getIPCountryCode(host)
	isNearRU := nearRUCountries[countryCode]
	ruSNI := isRuSNI(sni)
	hasBypassTech := security == "reality" || proto == "hysteria2" || proto == "hy2" || proto == "tuic" || flow != "" || strings.Contains(configStr, "fp=")

	adjustedPing := realPing
	if countryCode == "RU" {
		adjustedPing = time.Duration(float64(realPing) * 0.20)
	} else if isNearRU {
		adjustedPing = time.Duration(float64(realPing) * 0.50)
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

func checkTargetServicesViaProxy(configStr string) (int, bool) {
	corePath := findCoreExecutable()
	if corePath == "" {
		return 0, false
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, false
	}
	socksPort := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

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

	defer func() {
		_ = os.Remove(tmpConfigPath)
	}()

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
	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", socksAddr, 15*time.Millisecond)
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
		TLSHandshakeTimeout: 1500 * time.Millisecond,
	}
	defer httpTransport.CloseIdleConnections()

	client := &http.Client{
		Transport: httpTransport,
		Timeout:   1800 * time.Millisecond,
	}

	var wg sync.WaitGroup
	var successCount int64

	for _, service := range targetServices {
		wg.Add(1)
		go func(s TargetService) {
			defer wg.Done()
			reqCtx, reqCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
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
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()

			if s.ExpectedStatus(resp.StatusCode) {
				atomic.AddInt64(&successCount, 1)
			}
		}(service)
	}

	wg.Wait()
	totalSuccess := int(atomic.LoadInt64(&successCount))
	return totalSuccess, totalSuccess > 0
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

func ensureCoreAvailable() {
	if findCoreExecutable() != "" {
		return
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
		return
	}

	resp, err := sharedHTTPClient.Get(downloadURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	cwd, _ := os.Getwd()
	targetExe := "sing-box"
	if runtime.GOOS == "windows" {
		targetExe = "sing-box.exe"
	}

	if strings.HasSuffix(downloadURL, ".zip") {
		tmpZip, err := os.CreateTemp("", "sb_download_*.zip")
		if err != nil {
			return
		}
		defer os.Remove(tmpZip.Name())

		_, err = io.Copy(tmpZip, resp.Body)
		_ = tmpZip.Close()
		if err != nil {
			return
		}

		r, err := zip.OpenReader(tmpZip.Name())
		if err != nil {
			return
		}
		defer r.Close()

		for _, f := range r.File {
			if filepath.Base(f.Name) == targetExe {
				rc, err := f.Open()
				if err != nil {
					return
				}
				outPath := filepath.Join(cwd, targetExe)
				outFile, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
				if err != nil {
					_ = rc.Close()
					return
				}
				_, err = io.Copy(outFile, rc)
				_ = rc.Close()
				_ = outFile.Close()
				if err == nil {
					_ = os.Chmod(outPath, 0755)
					fmt.Printf("sing-box Core успешно развернут: (%s)\n", outPath)
				}
				break
			}
		}
	} else if strings.HasSuffix(downloadURL, ".tar.gz") {
		gzr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return
		}
		defer gzr.Close()

		tr := tar.NewReader(gzr)
		for {
			header, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return
			}
			if filepath.Base(header.Name) == targetExe {
				outPath := filepath.Join(cwd, targetExe)
				outFile, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
				if err != nil {
					return
				}
				_, err = io.Copy(outFile, tr)
				_ = outFile.Close()
				if err == nil {
					_ = os.Chmod(outPath, 0755)
					fmt.Printf("sing-box Core успешно развернут: (%s)\n", outPath)
				}
				break
			}
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
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512*1024))
			_ = resp.Body.Close()
		}
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512*1024))
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
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
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 4*1024*1024)

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
		ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
		defer cancel()
		ips, err := dnsResolver.LookupHost(ctx, host)
		if err != nil || len(ips) == 0 {
			return ""
		}
		ipStr = ips[0]
	}

	if val, ok := geoCache.Load(ipStr); ok {
		return val.(string)
	}

	reqCtx, reqCancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer reqCancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", "https://freeipapi.com/api/json/"+ipStr, nil)
	if err != nil {
		return ""
	}

	resp, err := sharedHTTPClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var res struct {
		CountryCode string `json:"countryCode"`
	}
	if json.NewDecoder(resp.Body).Decode(&res) == nil && res.CountryCode != "" {
		geoCache.Store(ipStr, res.CountryCode)
		return res.CountryCode
	}
	return ""
}

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
			if err := json.Unmarshal(decoded, &vmap); err == nil {
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

func parseConfigDetails(configStr string) (host string, port string, sni string, path string, transport string, proto string, security string, flow string) {
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
			return host, port, sni, "", "", "ss", "none", ""
		}

		raw := configStr[5:]
		if idx := strings.Index(raw, "#"); idx != -1 {
			raw = raw[:idx]
		}
		if idx := strings.Index(raw, "@"); idx != -1 {
			hostPort := raw[idx+1:]
			if hpHost, hpPort, err := net.SplitHostPort(hostPort); err == nil {
				return hpHost, hpPort, "", "", "", "ss", "none", ""
			}
		} else {
			if decoded, err := decodeBase64Flex(raw); err == nil {
				decStr := string(decoded)
				if idx := strings.Index(decStr, "@"); idx != -1 {
					hostPort := decStr[idx+1:]
					if hpHost, hpPort, err := net.SplitHostPort(hostPort); err == nil {
						return hpHost, hpPort, "", "", "", "ss", "none", ""
					}
				}
			}
		}
	}

	if strings.HasPrefix(configURL, "vmess://") && len(configStr) > 8 {
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
