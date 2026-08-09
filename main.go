package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	timeout        = 3 * time.Second
	maxConcurrency = 50
)

func main() {
	sources, err := readLines("sources.txt")
	if err != nil {
		fmt.Printf("Ошибка чтения sources.txt: %v\n", err)
		return
	}

	rawConfigs := make(chan string, 5000)
	var wg sync.WaitGroup

	// 1. Скачиваем подписки
	for _, src := range sources {
		if strings.TrimSpace(src) == "" || strings.HasPrefix(src, "#") {
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

	// 2. Дедупликация
	uniqueConfigs := make(map[string]bool)
	for cfg := range rawConfigs {
		cfg = strings.TrimSpace(cfg)
		if cfg != "" {
			uniqueConfigs[cfg] = true
		}
	}

	fmt.Printf("Собрано %d уникальных конфигов. Начинаем проверку доступности...\n", len(uniqueConfigs))

	// 3. Проверка TCP/Latency
	validConfigs := make(chan string, len(uniqueConfigs))
	semaphore := make(chan struct{}, maxConcurrency)
	var testWg sync.WaitGroup

	for cfg := range uniqueConfigs {
		testWg.Add(1)
		go func(c string) {
			defer testWg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if checkPing(c) {
				validConfigs <- c
			}
		}(cfg)
	}

	testWg.Wait()
	close(validConfigs)

	// 4. Сохранение результатов
	var finalSlice []string
	for v := range validConfigs {
		finalSlice = append(finalSlice, v)
	}

	fmt.Printf("Прошло проверку: %d конфигов.\n", len(finalSlice))

	rawOutput := strings.Join(finalSlice, "\n")
	os.WriteFile("output_raw.txt", []byte(rawOutput), 0644)

	b64Output := base64.StdEncoding.EncodeToString([]byte(rawOutput))
	os.WriteFile("output_base64.txt", []byte(b64Output), 0644)

	fmt.Println("Файлы output_raw.txt и output_base64.txt успешно сформированы.")
}

func fetchSubscription(targetURL string, out chan<- string) {
	client := http.Client{Timeout: 10 * time.Second}
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
	// Пробуем декодировать из Base64, если подписка полностью зашифрована
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content)); err == nil {
		content = string(decoded)
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if isProxyProtocol(line) {
			out <- line
		}
	}
}

func isProxyProtocol(line string) bool {
	protocols := []string{"vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria2://", "hy2://", "tuic://"}
	for _, p := range protocols {
		if strings.HasPrefix(line, p) {
			return true
		}
	}
	return false
}

func checkPing(configStr string) bool {
	host, port := parseHostPort(configStr)
	if host == "" || port == "" {
		return false
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func parseHostPort(configStr string) (string, string) {
	u, err := url.Parse(configStr)
	if err != nil {
		return "", ""
	}

	host := u.Hostname()
	port := u.Port()

	if port == "" {
		switch u.Scheme {
		case "vless", "vmess", "trojan", "hysteria2", "hy2":
			port = "443"
		case "ss":
			port = "8388"
		}
	}

	return host, port
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
