package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
    "regexp"
	"strings"
	"time"
)

const (
	httpPort = 8080
)

var (
	UUID         = getEnv("UUID", "9650d70e-2d06-4341-aa72-2705d6306e49")
	NEZHA_SERVER = getEnv("NEZHA_SERVER", "agent.oklala.filegear-sg.me")
	NEZHA_PORT   = getEnv("NEZHA_PORT", "443")
	NEZHA_KEY    = getEnv("NEZHA_KEY", "ThivksosPy3WcfJdqU")
	ARGO_DOMAIN  = getEnv("ARGO_DOMAIN", "a35.oklala.top")
	ARGO_AUTH    = getEnv("ARGO_AUTH", "eyJhIjoiYTUyYzFmMDk1MzAyNTU0YjA3NzJkNjU4ODI0MjRlMzUiLCJ0IjoiYjAyYzhmNzMtMjg5Ni00MzY3LWJlYTAtOTNmZGFkM2QwZmU3IiwicyI6Ik16Z3hNRGs1WmpNdE1UaGlOQzAwTldWbUxUa3dOVEV0WXpaa1pXUmpNV1EwTkdFMyJ9")
	NAME         = getEnv("NAME", "marscode")
	CFIP         = getEnv("CFIP", "hk.oklala.top")
	FILE_PATH    = getEnv("FILE_PATH", "/tmp")
	ARGO_PORT    = getEnv("ARGO_PORT", "8001")
)

func main() {
	go startHTTPServer()

	if _, err := os.Stat(FILE_PATH); os.IsNotExist(err) {
		os.Mkdir(FILE_PATH, 0755)
	}

	cleanupOldFiles()
	time.Sleep(2 * time.Second)

	generateConfig()
	time.Sleep(2 * time.Second)

	downloadFiles()
	configureArgo()
	time.Sleep(2 * time.Second)

	run()
	time.Sleep(3 * time.Second)

	generateLinks()
	time.Sleep(15 * time.Second)

	fmt.Println("\033[1;32mserver is running\033[0m")
	fmt.Println("\033[1;32mThank you for using this script, enjoy!\033[0m")

	select {}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func cleanupOldFiles() {
	files := []string{"boot.log", "sub.txt", "config.json", "tunnel.json", "tunnel.yml"}
	for _, file := range files {
		os.Remove(FILE_PATH + "/" + file)
	}
}

func generateConfig() {
	config := fmt.Sprintf(`
{
	"log": { "access": "/dev/null", "error": "/dev/null", "loglevel": "none" },
	"inbounds": [
		{
			"port": %s,
			"protocol": "vless",
			"settings": {
				"clients": [{ "id": "%s", "flow": "xtls-rprx-vision" }],
				"decryption": "none",
				"fallbacks": [
					{ "dest": 3001 }, { "path": "/vless", "dest": 3002 },
					{ "path": "/vmess", "dest": 3003 }, { "path": "/trojan", "dest": 3004 }
				]
			},
			"streamSettings": { "network": "tcp" }
		},
		{
			"port": 3001, "listen": "127.0.0.1", "protocol": "vless",
			"settings": { "clients": [{ "id": "%s" }], "decryption": "none" },
			"streamSettings": { "network": "ws", "security": "none" }
		},
		{
			"port": 3002, "listen": "127.0.0.1", "protocol": "vless",
			"settings": { "clients": [{ "id": "%s", "level": 0 }], "decryption": "none" },
			"streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vless" } },
			"sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "metadataOnly": false }
		},
		{
			"port": 3003, "listen": "127.0.0.1", "protocol": "vmess",
			"settings": { "clients": [{ "id": "%s", "alterId": 0 }] },
			"streamSettings": { "network": "ws", "wsSettings": { "path": "/vmess" } },
			"sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "metadataOnly": false }
		},
		{
			"port": 3004, "listen": "127.0.0.1", "protocol": "trojan",
			"settings": { "clients": [{ "password": "%s" }] },
			"streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/trojan" } },
			"sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "metadataOnly": false }
		}
	],
	"dns": { "servers": ["https+local://8.8.8.8/dns-query"] },
	"outbounds": [
		{ "protocol": "freedom" },
		{
			"tag": "WARP", "protocol": "wireguard",
			"settings": {
				"secretKey": "YFYOAdbw1bKTHlNNi+aEjBM3BO7unuFC5rOkMRAz9XY=",
				"address": ["172.16.0.2/32", "2606:4700:110:8a36:df92:102a:9602:fa18/128"],
				"peers": [{ "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "allowedIPs": ["0.0.0.0/0", "::/0"], "endpoint": "162.159.193.10:2408" }],
				"reserved": [78, 135, 76], "mtu": 1280
			}
		}
	],
	"routing": {
		"domainStrategy": "AsIs",
		"rules": [{ "type": "field", "domain": ["domain:openai.com", "domain:ai.com"], "outboundTag": "WARP" }]
	}
}`, ARGO_PORT, UUID, UUID, UUID, UUID, UUID)

	ioutil.WriteFile(FILE_PATH+"/config.json", []byte(config), 0644)
}

func downloadFiles() {
	arch := exec.Command("uname", "-m")
	output, _ := arch.Output()
	ARCH := strings.TrimSpace(string(output))

	var fileInfo []string
	if ARCH == "arm" || ARCH == "arm64" || ARCH == "aarch64" {
		fileInfo = []string{
			"https://github.com/eooce/test/releases/download/arm64/bot13 bot",
			"https://github.com/eooce/test/releases/download/ARM/web web",
			"https://github.com/eooce/test/releases/download/ARM/swith npm",
		}
	} else if ARCH == "amd64" || ARCH == "x86_64" || ARCH == "x86" {
		fileInfo = []string{
			"https://github.com/eooce/test/releases/download/amd64/bot13 bot",
			"https://github.com/eooce/test/releases/download/123/web web",
			"https://github.com/eooce/test/releases/download/bulid/swith npm",
		}
	} else {
		fmt.Printf("Unsupported architecture: %s\n", ARCH)
		os.Exit(1)
	}

	for _, entry := range fileInfo {
		urlFilename := strings.Split(entry, " ")
		URL := urlFilename[0]
		NEW_FILENAME := urlFilename[1]
		FILENAME := FILE_PATH + "/" + NEW_FILENAME
		cmd := exec.Command("curl", "-L", "-sS", "-o", FILENAME, URL)
		cmd.Run()
		fmt.Printf("\033[1;32mDownloading %s\033[0m\n", FILENAME)
	}

	for _, entry := range fileInfo {
		NEW_FILENAME := strings.Split(entry, " ")[1]
		FILENAME := FILE_PATH + "/" + NEW_FILENAME
		cmd := exec.Command("chmod", "+x", FILENAME)
		cmd.Run()
		fmt.Printf("\033[1;32m%s permission successfully\033[0m\n", FILENAME)
	}
}

func configureArgo() {
	if ARGO_AUTH == "" || ARGO_DOMAIN == "" {
		fmt.Println("\033[1;32mARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels\033[0m")
		return
	}

	if strings.Contains(ARGO_AUTH, "TunnelSecret") {
		ioutil.WriteFile(FILE_PATH+"/tunnel.json", []byte(ARGO_AUTH), 0644)
		tunnelConfig := fmt.Sprintf(`
tunnel: %s
credentials-file: %s/tunnel.json
protocol: http2

ingress:
	- hostname: %s
	  service: http://localhost:%s
	  originRequest:
		noTLSVerify: true
`, extractTunnelSecret(ARGO_AUTH), FILE_PATH, ARGO_DOMAIN, ARGO_PORT)
		ioutil.WriteFile(FILE_PATH+"/tunnel.yml", []byte(tunnelConfig), 0644)
	} else {
		fmt.Println("\033[1;32mARGO_AUTH mismatch TunnelSecret, use token connect to tunnel\033[0m")
	}
}

func extractTunnelSecret(auth string) string {
	// Extract the TunnelSecret from ARGO_AUTH
	return strings.Split(auth, "\"")[11]
}

func run() {
	runProcess("npm", NEZHA_SERVER, NEZHA_PORT, NEZHA_KEY)
	runProcess("web", "", "", "")
	runProcess("bot", "", "", "")
}

func runProcess(process, server, port, key string) {
	filePath := FILE_PATH + "/" + process
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Printf("\033[1;31mProcess file %s not found, skipping...\033[0m\n", filePath)
		return
	}

	cmd := exec.Command("chmod", "777", filePath)
	cmd.Run()

	var args []string
	if process == "npm" {
		tlsPorts := []string{"443", "8443", "2096", "2087", "2083", "2053"}
		NEZHA_TLS := ""
		for _, p := range tlsPorts {
			if p == NEZHA_PORT {
				NEZHA_TLS = "--tls"
				break
			}
		}

		if server != "" && port != "" && key != "" {
			args = []string{"-s", server + ":" + port, "-p", key, NEZHA_TLS}
			go runCommand(filePath, args)
			time.Sleep(1 * time.Second)
			checkProcess("npm", filePath, args)
		} else {
			fmt.Println("\033[1;35mNEZHA variable is empty, skipping running\033[0m")
		}
	} else if process == "web" {
		args = []string{"-c", FILE_PATH + "/config.json"}
		go runCommand(filePath, args)
		time.Sleep(2 * time.Second)
		checkProcess("web", filePath, args)
	} else if process == "bot" {
		fmt.Printf("Running bot with ARGO_AUTH: %s\n", ARGO_AUTH) // 添加调试信息

		if isValidToken(ARGO_AUTH) {
			args = []string{"tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2", "run", "--token", ARGO_AUTH}
		} else if strings.Contains(ARGO_AUTH, "TunnelSecret") {
			args = []string{"tunnel", "--edge-ip-version", "auto", "--config", FILE_PATH + "/tunnel.yml", "run"}
		} else {
			args = []string{"tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2", "--logfile", FILE_PATH + "/boot.log", "--loglevel", "info", "--url", "http://localhost:" + ARGO_PORT}
		}

		fmt.Printf("Running bot with args: %v\n", args) // 添加调试信息
		go runCommand(filePath, args)
		time.Sleep(3 * time.Second)
		checkProcess("bot", filePath, args)
	}
}

func isValidToken(auth string) bool {
	// 使用正则表达式检查 token 格式
	var tokenPattern = regexp.MustCompile(`^[A-Z0-9a-z=]{120,250}$`)
	return tokenPattern.MatchString(auth)
}

func runCommand(command string, args []string) {
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Start()
}

func checkProcess(name, command string, args []string) {
	if err := exec.Command("pgrep", "-x", name).Run(); err != nil {
		fmt.Printf("\033[1;35m%s is not running, restarting...\033[0m\n", name)
		exec.Command("pkill", "-x", name).Run()
		go runCommand(command, args)
		time.Sleep(2 * time.Second)
		fmt.Printf("\033[1;32m%s restarted\033[0m\n", name)
	} else {
		fmt.Printf("\033[1;32m%s is running\033[0m\n", name)
	}
}

func generateLinks() {
	argodomain := getArgoDomain()
	fmt.Printf("\033[1;32mArgodomain:\033[1;35m%s\033[0m\n", argodomain)
	time.Sleep(2 * time.Second)

	isp := getISP()
	time.Sleep(2 * time.Second)

	vmess := fmt.Sprintf(`{ "v": "2", "ps": "%s-%s", "add": "%s", "port": "443", "id": "%s", "aid": "0", "scy": "none", "net": "ws", "type": "none", "host": "%s", "path": "/vmess?ed=2048", "tls": "tls", "sni": "%s", "alpn": "" }`, NAME, isp, CFIP, UUID, argodomain, argodomain)

	listContent := fmt.Sprintf(`
vless://%s@%s:443?encryption=none&security=tls&sni=%s&type=ws&host=%s&path=%2Fvless?ed=2048#%s-%s

vmess://%s

trojan://%s@%s:443?security=tls&sni=%s&type=ws&host=%s&path=%2Ftrojan?ed=2048#%s-%s
`, UUID, CFIP, argodomain, argodomain, NAME, isp,
		base64.StdEncoding.EncodeToString([]byte(vmess)),
		UUID, CFIP, argodomain, argodomain, NAME, isp)

	ioutil.WriteFile(FILE_PATH+"/list.txt", []byte(listContent), 0644)
	subContent := base64.StdEncoding.EncodeToString([]byte(listContent))
	ioutil.WriteFile(FILE_PATH+"/sub.txt", []byte(subContent), 0644)

	fmt.Println(subContent)
	fmt.Printf("\n\033[1;32m%s/sub.txt saved successfully\033[0m\n", FILE_PATH)
	time.Sleep(8 * time.Second)

	cleanupOldFiles()
}

func getArgoDomain() string {
	if ARGO_AUTH != "" {
		return ARGO_DOMAIN
	}
	content, _ := ioutil.ReadFile(FILE_PATH + "/boot.log")
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.Contains(line, "trycloudflare.com") {
			parts := strings.Split(line, "//")
			if len(parts) > 1 {
				domain := strings.Split(parts[1], " ")[0]
				return domain
			}
		}
	}
	return ""
}

func getISP() string {
	cmd := exec.Command("curl", "-s", "https://speed.cloudflare.com/meta")
	output, _ := cmd.Output()
	data := strings.Split(string(output), "\"")
	if len(data) > 26 {
		isp := data[25] + "-" + data[17]
		return strings.ReplaceAll(isp, " ", "_")
	}
	return ""
}

func startHTTPServer() {
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/sub", subHandler)
	err := http.ListenAndServe(fmt.Sprintf(":%d", httpPort), nil)
	if err != nil {
		fmt.Printf("HTTP server error: %v\n", err)
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello, World!")
}

func subHandler(w http.ResponseWriter, r *http.Request) {
	content, err := ioutil.ReadFile(FILE_PATH + "/sub.txt")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading file: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	w.Write(content)
}
