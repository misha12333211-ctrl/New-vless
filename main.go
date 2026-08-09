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
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	timeout        = 3 * time.Second
	maxConcurrency = 80
	maxOutputLimit = 300 // Максимальное количество итоговых конфигов
)

type ConfigResult struct {
	URL     string
	Latency time.Duration
	Score   int
}

func main() {
	sources, err := readLines("sources.txt")
	if err != nil {
		fmt.Printf("Ошибка чтения sources.txt: %v\n", err)
		return
	}

	rawConfigs := make(chan string, 10000)
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

	fmt.Printf("Собрано %d уникальных конфигов. Начинаем глубокое тестирование...\n", len(uniqueConfigs))

	// 3. Проверка Latency и расчет рейтинга (Score)
	resultsChan := make(chan ConfigResult, len(uniqueConfigs))
	semaphore := make(chan struct{}, maxConcurrency)
	var testWg sync.WaitGroup

	for cfg := range uniqueConfigs {
		testWg.Add(1)
		go func(c string) {
			defer testWg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if res, ok := testConfig(c); ok {
				resultsChan <- res
			}
		}(cfg)
	}

	testWg.Wait()
	close(resultsChan)

	// 4. Сбор результатов
	var validResults []ConfigResult
	for res := range resultsChan {
		validResults = append(validResults, res)
	}

	fmt.Printf("Успешно ответили: %d конфигов.\n", len(validResults))

	// 5. Сортировка по очкам (чем больше Score, тем выше в списке)
	sort.Slice(validResults, func(i, j int) bool {
		return validResults[i].Score > validResults[j].Score
	})

	// 6. Ограничиваем топом из 300 самых лучших
	if len(validResults) > maxOutputLimit {
		validResults = validResults[:maxOutputLimit]
	}

	var finalSlice []string
	for _, r := range validResults {
		finalSlice = append(finalSlice, r.URL)
	}

	fmt.Printf("Отобрано ТОП-%d лучших конфигов.\n", len(finalSlice))

	// 7. Сохранение результатов
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

func testConfig(configStr string) (ConfigResult, bool) {
	host, port := parseHostPort(configStr)
	if host == "" || port == "" {
		return ConfigResult{}, false
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return ConfigResult{}, false
	}
	latency := time.Since(start)
	conn.Close()

	// Оценка стойкости к блокировкам ТСПУ
	score := calculateBypassScore(configStr, latency)

	return ConfigResult{
		URL:     configStr,
		Latency: latency,
		Score:   score,
	}, true
}

func calculateBypassScore(configStr string, latency time.Duration) int {
	score := 0
	lower := strings.ToLower(configStr)

	// 1. Приоритет протоколов и маскировки
	if strings.HasPrefix(lower, "vless://") {
		score += 70
		if strings.Contains(lower, "security=reality") {
			score += 50 // REALITY — лидер по обходу ТСПУ/белых списков
		} else if strings.Contains(lower, "security=tls") {
			score += 20
		}
		if strings.Contains(lower, "type=grpc") || strings.Contains(lower, "type=ws") {
			score += 15 // gRPC и WebSocket лучше маскируются под обычный веб-трафик
		}
	} else if strings.HasPrefix(lower, "hysteria2://") || strings.HasPrefix(lower, "hy2://") {
		score += 90 // Hysteria2 — отличный протокол для сложных условий и плохих сетей
	} else if strings.HasPrefix(lower, "tuic://") {
		score += 80
	} else if strings.HasPrefix(lower, "trojan://") {
		score += 40
	} else if strings.HasPrefix(lower, "vmess://") {
		score += 30
	} else {
		score += 10
	}

	// 2. Учитываем пинг (чем меньше пинг в мс, тем выше балл)
	pingMs := int(latency.Milliseconds())
	score -= pingMs / 10 // Каждые 10 мс пинга отнимают 1 очко

	return score
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
