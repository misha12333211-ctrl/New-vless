name: Aggregate Subscriptions

on:
  schedule:
    - cron: '0 */6 * * *' # Обновление каждые 6 часов
  workflow_dispatch:

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout private repo
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'
          cache: true

      - name: Build Aggregator Binary
        run: |
          if [ ! -f go.mod ]; then go mod init sub-aggregator; fi
          go build -o aggregator main.go

      - name: Run Aggregator
        run: ./aggregator

      - name: Deploy to Public Repo
        env:
          PUBLIC_TOKEN: ${{ secrets.PUBLIC_REPO_TOKEN }}
          PUBLIC_REPO: "misha12333211-ctrl/v2ray-aggregator-for-russia"
        run: |
          git config --global user.name "github-actions[bot]"
          git config --global user.email "github-actions[bot]@users.noreply.github.com"
          
          git clone https://x-access-token:${PUBLIC_TOKEN}@github.com/${PUBLIC_REPO}.git public_dist
          
          cp output_raw.txt public_dist/sub.txt
          cp output_base64.txt public_dist/sub_base64.txt
          
          cd public_dist
          git add sub.txt sub_base64.txt
          if git diff --staged --quiet; then
            echo "Изменений нет, пропуск пуша."
          else
            git commit -m "Auto-update subscriptions: $(date -u +'%Y-%m-%d %H:%M UTC')"
            git push
          fi
erviceSuccess: passedServices,
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

func checkTargetServicesViaProxy(configStr string) (int, bool) {
	corePath := findCoreExecutable()
	if corePath == "" {
		return 0, false
	}

	socksPort, listener, err := getFreePort()
	if err != nil {
		return 0, false
	}
	// Важно закрыть сокет, чтобы sing-box мог занять порт
	_ = listener.Close()

	singBoxConfigJSON, err := generateSingBoxConfig(configStr, socksPort)
	if err != nil {
		return 0, false
	}

	tmpConfigFile, err := os.CreateTemp("", "sb_cfg_*.json")
	if err != nil {
		return 0, false
	}
	tmpConfigPath := tmpConfigFile.Name()
	defer func() {
		_ = os.Remove(tmpConfigPath)
	}()

	_, _ = tmpConfigFile.Write(singBoxConfigJSON)
	_ = tmpConfigFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), serviceTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, corePath, "run", "-c", tmpConfigPath)

	// Гарантия жесткого принудительного убийства процессов на Linux/Unix
	if runtime.GOOS != "windows" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}

	if err := cmd.Start(); err != nil {
		return 0, false
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
	for i := 0; i < 40; i++ {
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
		TLSHandshakeTimeout: 2000 * time.Millisecond,
		ForceAttemptHTTP2:   false,
	}
	defer httpTransport.CloseIdleConnections()

	client := &http.Client{
		Transport: httpTransport,
		Timeout:   2200 * time.Millisecond,
	}

	var wg sync.WaitGroup
	var successCount int64

	for _, service := range targetServices {
		wg.Add(1)
		go func(s TargetService) {
			defer wg.Done()
			reqCtx, reqCancel := context.WithTimeout(ctx, 2000*time.Millisecond)
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
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 256*1024))
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

	scanner := bufio.NewScanner(strings.NewReader(content))
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

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

func getIPCountryCode(host string) string {
	ipStr := host
	if net.ParseIP(host) == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1000*time.Millisecond)
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

	if atomic.LoadInt64(&geoCacheSize) > maxGeoCacheEntries {
		return ""
	}

	client := &http.Client{Timeout: 800 * time.Millisecond}
	resp, err := client.Get("https://freeipapi.com/api/json/" + ipStr)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var res struct {
		CountryCode string `json:"countryCode"`
	}
	if json.NewDecoder(resp.Body).Decode(&res) == nil && res.CountryCode != "" {
		if atomic.AddInt64(&geoCacheSize, 1) <= maxGeoCacheEntries {
			geoCache.Store(ipStr, res.CountryCode)
		}
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

	if strings.HasPrefix(configURL, "vmess://") && len(configURL) > 8 {
		b64 := configURL[8:]
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
