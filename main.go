
package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
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
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	maxConcurrency     = 128 // Безопасно для GitHub Actions Runner
	maxOutputLimit     = 300 // Лимит конфигов в итоговой подписке
	pingTimeout        = 800 * time.Millisecond
	serviceTimeout     = 4500 * time.Millisecond
	fetchConcurrency   = 16
	maxGeoCacheEntries = 20000
)

type ConfigResult struct {
	URL            string
	Latency        time.Duration
	AdjustedPing   time.Duration
	Score          int
	ServiceSuccess int
	SNI            string
	Protocol       string
	Host           string
	CountryCode    string
	ISP            string
	IP             string
	IsNearRU       bool
	IsRuSNI        bool
	HasBypassTech  bool
}

type GeoInfo struct {
	IP          string
	CountryCode string
	ISP         string
}

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

// Карта стран с приоритетом поиска (бонусами)
// Все запрошенные страны: DE, AM, RU, IT, ES, NL, SE, PL, FI, US определены корректно
var countryPriorityMap = map[string]int{
	// Топ-Ближнее окружение
	"RU": 2500, "BY": 1800, "AM": 1800, "KZ": 1800, "GE": 1500, "MD": 1500, "UA": 1500,

	// Европа (Германия, Нидерланды, Швеция, Польша, Финляндия, Италия, Испания и др.)
	"DE": 1400, "NL": 1400, "FI": 1400, "SE": 1400, "PL": 1400, "IT": 1300, "ES": 1300,
	"EE": 1300, "LV": 1300, "LT": 1300, "AT": 1200, "FR": 1200, "GB": 1200, "CH": 1200,
	"CZ": 1200, "SK": 1200, "HU": 1200, "RO": 1200, "BG": 1200, "NO": 1200, "DK": 1200,

	// США и Северная Америка
	"US": 1100, "CA": 1000,

	// Другие популярные локации
	"TR": 1100, "AE": 1000, "SG": 1000, "JP": 900, "KR": 900, "HK": 900,
}

var (
	geoCache     sync.Map
	geoCacheSize int64
	dnsResolver  = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 800 * time.Millisecond}
			conn, err := d.DialContext(ctx, "udp", "77.88.8.8:53")
			if err != nil {
				return d.DialContext(ctx, "udp", "1.1.1.1:53")
			}
			return conn, nil
		},
	}
)

func main() {
	startTime := time.Now()

	fmt.Println("=== [1/5] Инициализация среды и ядра sing-box ===")
	ensureCoreAvailable()

	sources, err := readLines("sources.txt")
	if err != nil || len(sources) == 0 {
		fmt.Printf("Внимание: sources.txt не найден или пуст: %v. Создаем пустые выходы.\n", err)
		_ = os.WriteFile("output_raw.txt", []byte(""), 0644)
		_ = os.WriteFile("output_base64.txt", []byte(""), 0644)
		return
	}
	fmt.Printf("Успешно загружено источников: %d\n", len(sources))

	fmt.Println("=== [2/5] Сбор, фильтрация и Base64 декодирование ===")
	rawConfigs := make(chan string, 200000)
	var wg sync.WaitGroup

	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       15 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		DisableKeepAlives:     true,
	}

	sharedHTTPClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

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

	wg.Wait()
	close(rawConfigs)
	tr.CloseIdleConnections()

	uniqueConfigs := make(map[string]bool)
	for cfg := range rawConfigs {
		cfg = sanitizeProxyURL(cfg)
		if cfg != "" && len(cfg) < 4096 && isProxyProtocol(cfg) {
			uniqueConfigs[cfg] = true
		}
	}

	totalConfigs := len(uniqueConfigs)
	fmt.Printf("Валидных уникальных прокси-ссылок в базе: %d\n", totalConfigs)

	if totalConfigs == 0 {
		fmt.Println("Нет валидных конфигураций для тестирования. Завершение работы.")
		_ = os.WriteFile("output_raw.txt", []byte(""), 0644)
		_ = os.WriteFile("output_base64.txt", []byte(""), 0644)
		return
	}

	debug.FreeOSMemory()

	fmt.Println("=== [3/5] Высокоскоростное тестирование доступности и проверка IP через sing-box ===")
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

			if res, ok := testConfigFast(c); ok {
				resultsChan <- res
			}

			curr := atomic.AddInt64(&processedCount, 1)
			if curr%500 == 0 || curr == int64(totalConfigs) {
				fmt.Printf("Обработано конфигураций: %d / %d\r", curr, totalConfigs)
			}
		}(cfg)
	}

	testWg.Wait()
	close(resultsChan)
	fmt.Println("\nТестирование доступности полностью завершено.")

	var rawValidResults []ConfigResult
	for res := range resultsChan {
		if res.ServiceSuccess >= 1 {
			rawValidResults = append(rawValidResults, res)
		}
	}

	fmt.Printf("=== [4/5] GeoIP Обогащение и ранжирование (Прошло тест: %d) ===\n", len(rawValidResults))

	validResults := enrichWithGeoIPParallel(rawValidResults)
	protoStats := make(map[string]int)
	countryStats := make(map[string]int)

	for _, res := range validResults {
		protoStats[res.Protocol]++
		cc := res.CountryCode
		if cc == "" {
			cc = "UNK"
		}
		countryStats[cc]++
	}

	fmt.Println("Статистика по протоколам:")
	for proto, count := range protoStats {
		fmt.Printf("  • %s: %d шт.\n", strings.ToUpper(proto), count)
	}

	fmt.Println("Статистика по обнаруженным странам:")
	for country, count := range countryStats {
		fmt.Printf("  • %s %s: %d шт.\n", countryCodeToFlag(country), country, count)
	}

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
		flag := countryCodeToFlag(r.CountryCode)
		countryStr := r.CountryCode
		if countryStr == "" {
			countryStr = "LOC"
		}

		sniTag := ""
		if r.IsRuSNI {
			sniTag = " [SNI-RU]"
		}

		displayName := fmt.Sprintf("%s %s%s | TG: MiGiTi_official_channel #%d", flag, countryStr, sniTag, i+1)
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
	_ = os.WriteFile("output_raw.txt", []byte(rawOutput), 0644)

	b64Output := base64.StdEncoding.EncodeToString([]byte(rawOutput))
	_ = os.WriteFile("output_base64.txt", []byte(b64Output), 0644)

	debug.FreeOSMemory()
	fmt.Printf("Задание успешно выполнено за %v!\n", time.Since(startTime))
}

func testConfigFast(configStr string) (ConfigResult, bool) {
	host, port, sni, _, _, proto, security, flow := parseConfigDetails(configStr)
	if host == "" || port == "" {
		return ConfigResult{}, false
	}

	ruSNI := isRuSNI(sni)
	hasBypassTech := security == "reality" || proto == "hysteria2" || proto == "hy2" || proto == "tuic" || flow != "" || strings.Contains(configStr, "fp=")

	if !passTSPUBypassFilter(proto, port, sni, security, configStr) {
		return ConfigResult{}, false
	}

	realPing, ok := measureTCPPing(host, port)
	if !ok || realPing > pingTimeout {
		return ConfigResult{}, false
	}

	passedServices, realExitIP, ok := checkTargetServicesViaProxy(configStr)
	if !ok || passedServices < 1 {
		return ConfigResult{}, false
	}

	finalHostIP := host
	if realExitIP != "" {
		finalHostIP = realExitIP
	}

	return ConfigResult{
		URL:            configStr,
		Latency:        realPing,
		SNI:            sni,
		Protocol:       proto,
		Host:           finalHostIP,
		ServiceSuccess: passedServices,
		IsRuSNI:        ruSNI,
		HasBypassTech:  hasBypassTech,
	}, true
}

func enrichWithGeoIPParallel(results []ConfigResult) []ConfigResult {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 30)
	enriched := make([]ConfigResult, len(results))

	for i, res := range results {
		wg.Add(1)
		go func(idx int, r ConfigResult) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			geoInfo := getGeoInfo(r.Host)

			adjustedPing := r.Latency
			if geoInfo.CountryCode == "RU" || geoInfo.CountryCode == "AM" || geoInfo.CountryCode == "BY" {
				adjustedPing = time.Duration(float64(r.Latency) * 0.30)
			} else if countryPriorityMap[geoInfo.CountryCode] > 1200 {
				adjustedPing = time.Duration(float64(r.Latency) * 0.60)
			}

			score := calculateBypassScore(r.URL, "", r.SNI, "", adjustedPing, r.ServiceSuccess, geoInfo.CountryCode, r.IsRuSNI, r.HasBypassTech)

			r.CountryCode = geoInfo.CountryCode
			r.ISP = geoInfo.ISP
			r.IP = geoInfo.IP
			r.AdjustedPing = adjustedPing
			r.Score = score

			enriched[idx] = r
		}(i, res)
	}

	wg.Wait()
	return enriched
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

func measureTCPPing(host string, port string) (time.Duration, bool) {
	address := net.JoinHostPort(host, port)
	start := time.Now()

	d := net.Dialer{Timeout: pingTimeout}
	conn, err := d.Dial("tcp", address)
	if err != nil {
		return 0, false
	}
	_ = conn.Close()
	return time.Since(start), true
}

func getFreePort() (int, net.Listener, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	return port, l, nil
}

func checkTargetServicesViaProxy(configStr string) (int, string, bool) {
	corePath := findCoreExecutable()
	if corePath == "" {
		return 0, "", false
	}

	socksPort, listener, err := getFreePort()
	if err != nil {
		return 0, "", false
	}
	_ = listener.Close()

	singBoxConfigJSON, err := generateSingBoxConfig(configStr, socksPort)
	if err != nil {
		return 0, "", false
	}

	tmpConfigFile, err := os.CreateTemp("", "sb_cfg_*.json")
	if err != nil {
		return 0, "", false
	}
	tmpConfigPath := tmpConfigFile.Name()
	defer os.Remove(tmpConfigPath)

	_, _ = tmpConfigFile.Write(singBoxConfigJSON)
	_ = tmpConfigFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), serviceTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, corePath, "run", "-c", tmpConfigPath)

	if runtime.GOOS != "windows" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}

	if err := cmd.Start(); err != nil {
		return 0, "", false
	}

	defer func() {
		if cmd.Process != nil {
			if runtime.GOOS != "windows" {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			} else {
				_ = cmd.Process.Kill()
			}
		}
		_ = cmd.Wait()
	}()

	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	proxyReady := false
	for i := 0; i < 25; i++ {
		conn, err := net.DialTimeout("tcp", socksAddr, 5*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			proxyReady = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if !proxyReady {
		return 0, "", false
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

	var wg sync.WaitGroup
	var successCount int64
	var realExitIP string
	var ipOnce sync.Once

	wg.Add(1)
	go func() {
		defer wg.Done()
		reqCtx, reqCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer reqCancel()

		req, err := http.NewRequestWithContext(reqCtx, "GET", "https://api.ipify.org?format=json", nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		var ipRes struct {
			IP string `json:"ip"`
		}
		if json.NewDecoder(resp.Body).Decode(&ipRes) == nil && ipRes.IP != "" {
			ipOnce.Do(func() {
				realExitIP = strings.TrimSpace(ipRes.IP)
			})
		}
	}()

	for _, service := range targetServices {
		wg.Add(1)
		go func(s TargetService) {
			defer wg.Done()
			reqCtx, reqCancel := context.WithTimeout(ctx, 1200*time.Millisecond)
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
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16*1024))
			_ = resp.Body.Close()

			if s.ExpectedStatus(resp.StatusCode) {
				atomic.AddInt64(&successCount, 1)
			}
		}(service)
	}

	wg.Wait()
	totalSuccess := int(atomic.LoadInt64(&successCount))
	return totalSuccess, realExitIP, totalSuccess > 0
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
	version := "1.10.1"

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

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(downloadURL)
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
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 128*1024))
			_ = resp.Body.Close()
		}
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 128*1024))
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
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
	scanner.Buffer(buf, 5*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if isProxyProtocol(line) {
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

func countryCodeToFlag(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 {
		return "🌐"
	}
	runes := []rune(code)
	if runes[0] < 'A' || runes[0] > 'Z' || runes[1] < 'A' || runes[1] > 'Z' {
		return "🌐"
	}
	return string([]rune{runes[0] + 0x1F1A5, runes[1] + 0x1F1A5})
}

func getGeoInfo(host string) GeoInfo {
	ipStr := host
	if net.ParseIP(host) == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		ips, err := dnsResolver.LookupHost(ctx, host)
		if err != nil || len(ips) == 0 {
			return GeoInfo{IP: host, CountryCode: "", ISP: "Unknown"}
		}
		ipStr = ips[0]
	}

	if val, ok := geoCache.Load(ipStr); ok {
		return val.(GeoInfo)
	}

	if atomic.LoadInt64(&geoCacheSize) > maxGeoCacheEntries {
		return GeoInfo{IP: ipStr, CountryCode: "", ISP: "Unknown"}
	}

	client := &http.Client{Timeout: 700 * time.Millisecond}
	resp, err := client.Get("http://ip-api.com/json/" + ipStr + "?fields=countryCode,isp,org")
	if err != nil {
		emptyInfo := GeoInfo{IP: ipStr, CountryCode: "", ISP: "Unknown"}
		geoCache.Store(ipStr, emptyInfo)
		return emptyInfo
	}
	defer resp.Body.Close()

	var res struct {
		CountryCode string `json:"countryCode"`
		ISP         string `json:"isp"`
		Org         string `json:"org"`
	}

	if json.NewDecoder(resp.Body).Decode(&res) == nil {
		ispName := res.ISP
		if ispName == "" {
			ispName = res.Org
		}
		if ispName == "" {
			ispName = "Server"
		}

		info := GeoInfo{
			IP:          ipStr,
			CountryCode: res.CountryCode,
			ISP:         ispName,
		}

		if atomic.AddInt64(&geoCacheSize, 1) <= maxGeoCacheEntries {
			geoCache.Store(ipStr, info)
		}
		return info
	}

	emptyInfo := GeoInfo{IP: ipStr, CountryCode: "", ISP: "Unknown"}
	geoCache.Store(ipStr, emptyInfo)
	return emptyInfo
}

func calculateBypassScore(configStr string, port string, sni string, transport string, latency time.Duration, passedServices int, countryCode string, ruSNI bool, hasBypassTech bool) int {
	score := 100 + (passedServices * 500)

	// Добавляем бонус в зависимости от ценности страны
	if priorityBonus, exists := countryPriorityMap[countryCode]; exists {
		score += priorityBonus
	} else {
		score += 500 // Минимальный базовый бонус для любых других зарубежных стран
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

	if strings.HasPrefix(configStr, "vmess://") && len(configStr) > 8 {
		b64 := configStr[8:]
		if idx := strings.Index(b64, "#"); idx != -1 {
			b64 = b64[:idx]
		}
		decoded, err := decodeBase64Flex(b64)
		if err == nil {
			var vmap map[string]interface{}
			if err := json.Unmarshal(decoded, &vmap); err == nil && vmap != nil {
				if h, ok := vmap["add"].(string); ok {
					host = h
				}
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
				if s, ok := vmap["sni"].(string); ok {
					sni = s
				}
				if sni == "" {
					if h, ok := vmap["host"].(string); ok {
						sni = h
					}
				}
				if pth, ok := vmap["path"].(string); ok {
					path = pth
				}
				if n, ok := vmap["net"].(string); ok {
					transport = n
				}
				if t, ok := vmap["tls"].(string); ok {
					security = t
				}
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
