package main

import (
    "bufio"
    "encoding/json"
    "flag"
    "fmt"
    "html/template"
    "io"
    "log"
    "net/http"
    "os"
    "os/exec"
    "os/signal"
    "path/filepath"
    "sort"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/fatih/color"
)

type GlobalSettings struct {
    LogFile     string
    LogLevel    string
    Config      []SSHTunnelConfig
    Clients     map[string]*SSHClient
    ConfigPath  string
    WebHost     string
    WebPort     string
    StopChan    chan struct{}
    NoAutoStart bool
    Mutex       sync.Mutex
}

var globalSettings = &GlobalSettings{
    LogFile:  "ssh_tunnel_manager.log",
    LogLevel: "DEBUG",
    Clients:  make(map[string]*SSHClient),
    WebHost:  "127.0.0.1",
    WebPort:  "9988",
    StopChan: make(chan struct{}),
}

type SSHTunnelConfig struct {
    Name           string   `json:"name"`
    Host           string   `json:"host"`
    Port           int      `json:"port"`
    Username       string   `json:"username"`
    Password       string   `json:"password"`
    LocalPort      int      `json:"local_port"`
    Group          string   `json:"group"`
    Comment        string   `json:"comment"`
    SSHOptions     []string `json:"ssh_options"`
    SerialNumber   int      `json:"serial_number"`
    MaxReconnects  int      `json:"max_reconnects"`
    AutoReconnects int      `json:"auto_reconnects"`
}

type SSHClient struct {
    Config            SSHTunnelConfig
    Cmd               *exec.Cmd
    Status            string
    StopChan          chan struct{}
    StopOnce          sync.Once
    ReconnectAttempts int
    Mutex             sync.Mutex
    LogFile           *os.File
    WaitCalled        bool
}

var funcMap = template.FuncMap{
    "add": func(a, b int) int {
        return a + b
    },
    "capitalize": func(s string) string {
        if len(s) == 0 {
            return s
        }
        return strings.ToUpper(s[:1]) + s[1:]
    },
    "safeID": func(s string) string {
        s = strings.ToLower(s)
        s = strings.ReplaceAll(s, " ", "_")
        s = strings.ReplaceAll(s, "/", "_")
        s = strings.ReplaceAll(s, "\\", "_")
        // Удаляем специальные символы
        s = strings.Map(func(r rune) rune {
            if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
                return r
            }
            return -1
        }, s)
        return s
    },
}

var tmpl *template.Template

func main() {
    defer func() {
        if r := recover(); r != nil {
            logError("Application panicked: %v", r)
            cleanup()
            os.Exit(1)
        }
    }()

    parseArguments()
    setupLogging()
    logInfo("SSH Tunnel Manager starting...")
    loadConfig(globalSettings.ConfigPath)
    initClients()
    setupSignalHandlers()
    go monitorClients()

    var err error
    tmpl, err = template.New("index.html").Funcs(funcMap).ParseFiles("templates/index.html")
    if err != nil {
        log.Fatalf("Error parsing template: %v", err)
    }

    startWebServer()
}

func parseArguments() {
    var (
        showHelp    bool
        configPath  string
        logLevel    string
        webHost     string
        webPort     string
        noAutoStart bool
    )

    flag.BoolVar(&showHelp, "h", false, "Show help message")
    flag.BoolVar(&showHelp, "help", false, "Show help message")
    flag.StringVar(&configPath, "c", "", "Path to JSON configuration file")
    flag.StringVar(&configPath, "config", "", "Path to JSON configuration file")
    flag.StringVar(&logLevel, "log-level", "DEBUG", "Set logging level (DEBUG, INFO, WARNING, ERROR)")
    flag.StringVar(&webHost, "web-host", "127.0.0.1", "Host for the web interface")
    flag.StringVar(&webPort, "web-port", "9966", "Port for the web interface")
    flag.BoolVar(&noAutoStart, "no-auto-connect", false, "Disable auto connection of SSH tunnels on startup")
    flag.Parse()

    if showHelp {
        fmt.Println("Usage:")
        fmt.Println("  ssh_tunnel_manager -c config.json [options]")
        fmt.Println("")
        fmt.Println("Options:")
        fmt.Println("  -c, --config        Path to JSON configuration file (required)")
        fmt.Println("  --log-level         Set logging level (DEBUG, INFO, WARNING, ERROR) (default: INFO)")
        fmt.Println("  --web-host          Host for the web interface (default: 127.0.0.1)")
        fmt.Println("  --web-port          Port for the web interface (default: 9966)")
        fmt.Println("  --no-auto-connect   Disable auto connection of SSH tunnels on startup")
        fmt.Println("  -h, --help          Show help message")
        os.Exit(0)
    }

    if configPath == "" {
        logError("Configuration file is required. Use -c config.json")
        os.Exit(1)
    }

    globalSettings.ConfigPath = configPath
    globalSettings.LogLevel = strings.ToUpper(logLevel)
    globalSettings.WebHost = webHost
    globalSettings.WebPort = webPort
    globalSettings.NoAutoStart = noAutoStart
}

func setupLogging() {
    logFile, err := os.OpenFile(globalSettings.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatalf("Failed to open log file: %v", err)
    }

    mw := io.MultiWriter(os.Stdout, logFile)
    log.SetOutput(mw)
    log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
}

func loadConfig(configPath string) {
    data, err := os.ReadFile(configPath)
    if err != nil {
        logError("Failed to read config file: %v", err)
        os.Exit(1)
    }

    var config []SSHTunnelConfig
    if err := json.Unmarshal(data, &config); err != nil {
        logError("Config file is not valid JSON: %v", err)
        os.Exit(1)
    }

    validateConfig(config)
    globalSettings.Config = config
}

func validateConfig(config []SSHTunnelConfig) {
    for idx, sshConfig := range config {
        if sshConfig.Name == "" || sshConfig.Host == "" || sshConfig.Username == "" || sshConfig.LocalPort == 0 {
            logError("Invalid configuration at index %d: missing required fields.", idx)
            os.Exit(1)
        }
    }
}

func initClients() {
    for idx, sshConfig := range globalSettings.Config {
        sshConfig.SerialNumber = idx + 1
        client := &SSHClient{
            Config:   sshConfig,
            Status:   "stopped",
            StopChan: make(chan struct{}),
        }
        globalSettings.Clients[sshConfig.Name] = client

        if !globalSettings.NoAutoStart {
            go client.Start()
        }
    }
}

func (client *SSHClient) Start() {
    client.Mutex.Lock()
    if client.Status == "running" {
        client.Mutex.Unlock()
        logWarning("SSH tunnel '%s' is already running.", client.Config.Name)
        return
    }
    client.Status = "running"
    client.Mutex.Unlock()

    client.ReconnectAttempts = 0
    client.StopChan = make(chan struct{})
    client.StopOnce = sync.Once{}
    client.WaitCalled = false

    for {
        select {
        case <-client.StopChan:
            client.StopProcess()
            return
        default:
            client.StartProcess()
            if client.Config.AutoReconnects > 0 && client.ReconnectAttempts < client.Config.MaxReconnects {
                client.ReconnectAttempts++
                logWarning("SSH tunnel '%s' disconnected. Reconnecting... (%d/%d)", client.Config.Name, client.ReconnectAttempts, client.Config.MaxReconnects)
                time.Sleep(5 * time.Second)
            } else {
                client.setStatus("stopped")
                return
            }
        }
    }
}

func (client *SSHClient) StartProcess() {
    sshCommand := client.buildSSHCommand()
    logInfo("Starting SSH tunnel '%s' [Local Port: %d] -> [Remote Host: %s:%d]", client.Config.Name, client.Config.LocalPort, client.Config.Host, client.Config.Port)

    logDir := "logs"
    os.MkdirAll(logDir, 0755)
    logFilePath := filepath.Join(logDir, fmt.Sprintf("%s.log", client.Config.Name))
    logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        logError("Error opening log file for tunnel '%s': %v", client.Config.Name, err)
        client.setStatus("error")
        return
    }
    client.LogFile = logFile
    defer client.LogFile.Close()

    cmd := exec.Command(sshCommand[0], sshCommand[1:]...)
    client.Cmd = cmd

    stdoutPipe, err := cmd.StdoutPipe()
    if err != nil {
        logError("Error getting stdout pipe: %v", err)
        client.setStatus("error")
        return
    }
    stderrPipe, err := cmd.StderrPipe()
    if err != nil {
        logError("Error getting stderr pipe: %v", err)
        client.setStatus("error")
        return
    }

    logDebug("Executing SSH command for tunnel '%s': %s", client.Config.Name, strings.Join(cmd.Args, " "))

    if err := cmd.Start(); err != nil {
        logError("Error starting SSH tunnel '%s': %v", client.Config.Name, err)
        client.setStatus("error")
        return
    }

    client.setStatus("running")

    go client.readPipe(stdoutPipe)
    go client.readPipe(stderrPipe)

    err = cmd.Wait()
    client.WaitCalled = true
    if err != nil {
        logError("SSH tunnel '%s' exited with error: %v", client.Config.Name, err)
        client.setStatus("stopped")
    } else {
        logInfo("SSH tunnel '%s' exited.", client.Config.Name)
        client.setStatus("stopped")
    }
}

func (client *SSHClient) readPipe(pipe io.ReadCloser) {
    scanner := bufio.NewScanner(pipe)
    for scanner.Scan() {
        line := scanner.Text()
        timestamp := time.Now().Format("2006-01-02 15:04:05.000")
        message := fmt.Sprintf("%s - [%s] %s\n", timestamp, client.Config.Name, line)
        client.LogFile.WriteString(message)
    }
}

func (client *SSHClient) buildSSHCommand() []string {
    sshConfig := client.Config
    command := []string{}

    if sshConfig.Password != "" {
        command = append(command, "sshpass", "-p", sshConfig.Password)
    }
    command = append(command, "ssh")
    command = append(command, "-D", strconv.Itoa(sshConfig.LocalPort))
    command = append(command, "-N")
    command = append(command, "-o", "ServerAliveInterval=60")
    command = append(command, "-o", "ServerAliveCountMax=3")
    command = append(command, "-o", "TCPKeepAlive=yes")
    command = append(command, "-o", "LogLevel=DEBUG")
    command = append(command, "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no")

    // Add the requested SSH options for compatibility
    ciphers := "3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com"
    macs := "hmac-sha1,hmac-sha1-96,hmac-sha2-256,hmac-sha2-512,hmac-md5,hmac-md5-96,umac-64@openssh.com,umac-128@openssh.com"
    kexAlgorithms := "diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,curve25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"
    hostKeyAlgorithms := "ssh-rsa"


    command = append(command, "-o", fmt.Sprintf("Ciphers=%s", ciphers))
    command = append(command, "-o", fmt.Sprintf("MACs=%s", macs))
    command = append(command, "-o", fmt.Sprintf("KexAlgorithms=%s", kexAlgorithms))
    command = append(command, "-o", fmt.Sprintf("HostKeyAlgorithms=%s", hostKeyAlgorithms))

    if len(sshConfig.SSHOptions) > 0 {
        command = append(command, sshConfig.SSHOptions...)
    }

    if sshConfig.Port != 0 {
        command = append(command, "-p", strconv.Itoa(sshConfig.Port))
    }

    command = append(command, fmt.Sprintf("%s@%s", sshConfig.Username, sshConfig.Host))
    return command
}

func (client *SSHClient) Stop() {
    client.Mutex.Lock()
    if client.Status != "running" {
        client.Mutex.Unlock()
        return
    }
    client.Status = "stopped"
    client.Mutex.Unlock()
    client.StopOnce.Do(func() {
        close(client.StopChan)
    })
    client.StopProcess()
}

func (client *SSHClient) StopProcess() {
    if client.Cmd != nil && client.Cmd.Process != nil {
        if client.Cmd.ProcessState != nil && client.Cmd.ProcessState.Exited() {
            logInfo("SSH tunnel '%s' has already exited.", client.Config.Name)
            return
        }
        logInfo("Stopping SSH tunnel '%s'...", client.Config.Name)
        err := client.Cmd.Process.Signal(syscall.SIGTERM)
        if err != nil {
            if err.Error() == "os: process already finished" {
                logInfo("SSH tunnel '%s' has already exited.", client.Config.Name)
                return
            }
            logError("Error sending SIGTERM to SSH tunnel '%s': %v", client.Config.Name, err)
        }
        if !client.WaitCalled {
            err = client.Cmd.Wait()
            client.WaitCalled = true
            if err != nil {
                logError("SSH tunnel '%s' exited with error: %v", client.Config.Name, err)
            } else {
                logInfo("SSH tunnel '%s' stopped.", client.Config.Name)
            }
        } else {
            logInfo("Wait has already been called for SSH tunnel '%s'.", client.Config.Name)
        }
    } else {
        logInfo("SSH tunnel '%s' is not running.", client.Config.Name)
    }
}

func (client *SSHClient) setStatus(status string) {
    client.Mutex.Lock()
    client.Status = status
    client.Mutex.Unlock()
}

func monitorClients() {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            for _, client := range globalSettings.Clients {
                client.Mutex.Lock()
                status := client.Status
                client.Mutex.Unlock()
                if status != "running" && client.Config.AutoReconnects > 0 {
                    go client.Start()
                }
            }
        case <-globalSettings.StopChan:
            return
        }
    }
}

func setupSignalHandlers() {
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        sig := <-c
        logInfo("Received signal: %v", sig)
        cleanup()
        os.Exit(0)
    }()
}

func cleanup() {
    close(globalSettings.StopChan)
    stopAllClients()
    logInfo("SSH Tunnel Manager stopped.")
}

func stopAllClients() {
    for _, client := range globalSettings.Clients {
        client.Stop()
    }
}

func startWebServer() {
    defer func() {
        if r := recover(); r != nil {
            logError("Web server panicked: %v", r)
        }
    }()

    http.HandleFunc("/", indexHandler)
    http.HandleFunc("/start", startTunnelHandler)
    http.HandleFunc("/stop", stopTunnelHandler)
    http.HandleFunc("/restart", restartTunnelHandler)
    http.HandleFunc("/add", addTunnelHandler)
    http.HandleFunc("/edit", editTunnelHandler)
    http.HandleFunc("/edit_global", editGlobalHandler)
    http.HandleFunc("/delete", deleteTunnelHandler)
    http.HandleFunc("/logs", logsHandler)
    http.HandleFunc("/toggle_theme", toggleThemeHandler)
    http.HandleFunc("/bulk_action", bulkActionHandler)

    addr := globalSettings.WebHost + ":" + globalSettings.WebPort
    logInfo("Starting web server at %s...", addr)
    if err := http.ListenAndServe(addr, nil); err != nil {
        logError("Failed to start web server: %v", err)
        cleanup()
        os.Exit(1)
    }
}

// HTTP Handlers

func indexHandler(w http.ResponseWriter, r *http.Request) {
    data := struct {
        Tunnels           []*SSHClient
        TotalTunnels      int
        ActiveTunnels     int
        ErrorTunnels      int
        RestartingTunnels int
        Theme             string
        GroupedTunnels    map[string][]*SSHClient
        Page              string
    }{
        Tunnels:           getTunnelList(),
        TotalTunnels:      len(globalSettings.Clients),
        ActiveTunnels:     getActiveTunnelCount(),
        ErrorTunnels:      getErrorTunnelCount(),
        RestartingTunnels: getRestartingTunnelCount(),
        Theme:             getThemeFromCookie(r),
        GroupedTunnels:    getGroupedTunnels(),
        Page:              "index",
    }

    if err := tmpl.Execute(w, data); err != nil {
        logError("Error executing template: %v", err)
    }
}

func startTunnelHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    tunnelName := r.FormValue("name")
    client, ok := globalSettings.Clients[tunnelName]
    if ok {
        logInfo("Starting tunnel '%s' via web interface", tunnelName)
        go client.Start()
    } else {
        logWarning("Tunnel '%s' not found", tunnelName)
    }
    http.Redirect(w, r, "/", http.StatusFound)
}

func stopTunnelHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    tunnelName := r.FormValue("name")
    client, ok := globalSettings.Clients[tunnelName]
    if ok {
        logInfo("Stopping tunnel '%s' via web interface", tunnelName)
        client.Stop()
    } else {
        logWarning("Tunnel '%s' not found", tunnelName)
    }
    http.Redirect(w, r, "/", http.StatusFound)
}

func restartTunnelHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    tunnelName := r.FormValue("name")
    client, ok := globalSettings.Clients[tunnelName]
    if ok {
        logInfo("Restarting tunnel '%s' via web interface", tunnelName)
        client.Stop()
        go client.Start()
    } else {
        logWarning("Tunnel '%s' not found", tunnelName)
    }
    http.Redirect(w, r, "/", http.StatusFound)
}

func addTunnelHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        data := struct {
            Theme string
            Page  string
        }{
            Theme: getThemeFromCookie(r),
            Page:  "add",
        }
        if err := tmpl.Execute(w, data); err != nil {
            logError("Error executing template: %v", err)
        }
    } else if r.Method == http.MethodPost {
        r.ParseForm()
        name := r.FormValue("name")
        host := r.FormValue("host")
        port, _ := strconv.Atoi(r.FormValue("port"))
        username := r.FormValue("username")
        password := r.FormValue("password")
        localPort, _ := strconv.Atoi(r.FormValue("local_port"))
        group := r.FormValue("group")
        comment := r.FormValue("comment")
        maxReconnects, _ := strconv.Atoi(r.FormValue("max_reconnects"))
        autoReconnects, _ := strconv.Atoi(r.FormValue("auto_reconnects"))

        serialNumber := len(globalSettings.Config) + 1

        sshConfig := SSHTunnelConfig{
            Name:           name,
            Host:           host,
            Port:           port,
            Username:       username,
            Password:       password,
            LocalPort:      localPort,
            Group:          group,
            Comment:        comment,
            SerialNumber:   serialNumber,
            MaxReconnects:  maxReconnects,
            AutoReconnects: autoReconnects,
            SSHOptions:     []string{},
        }

        globalSettings.Config = append(globalSettings.Config, sshConfig)
        saveConfig()

        client := &SSHClient{
            Config:   sshConfig,
            Status:   "stopped",
            StopChan: make(chan struct{}),
        }
        globalSettings.Clients[sshConfig.Name] = client

        logInfo("Added new tunnel '%s' via web interface", name)
        http.Redirect(w, r, "/", http.StatusFound)
    }
}

func editTunnelHandler(w http.ResponseWriter, r *http.Request) {
    tunnelName := r.URL.Query().Get("name")
    client, ok := globalSettings.Clients[tunnelName]
    if !ok {
        logWarning("Tunnel '%s' not found", tunnelName)
        http.Redirect(w, r, "/", http.StatusFound)
        return
    }

    if r.Method == http.MethodGet {
        data := struct {
            Theme  string
            Page   string
            Tunnel *SSHClient
        }{
            Theme:  getThemeFromCookie(r),
            Page:   "edit",
            Tunnel: client,
        }
        if err := tmpl.Execute(w, data); err != nil {
            logError("Error executing template: %v", err)
        }
    } else if r.Method == http.MethodPost {
        r.ParseForm()
        oldName := client.Config.Name
        client.Config.Name = r.FormValue("name")
        client.Config.Host = r.FormValue("host")
        client.Config.Port, _ = strconv.Atoi(r.FormValue("port"))
        client.Config.Username = r.FormValue("username")
        client.Config.Password = r.FormValue("password")
        client.Config.LocalPort, _ = strconv.Atoi(r.FormValue("local_port"))
        client.Config.Group = r.FormValue("group")
        client.Config.Comment = r.FormValue("comment")
        client.Config.MaxReconnects, _ = strconv.Atoi(r.FormValue("max_reconnects"))
        client.Config.AutoReconnects, _ = strconv.Atoi(r.FormValue("auto_reconnects"))

        // Обновляем конфигурацию в globalSettings.Config
        for idx, cfg := range globalSettings.Config {
            if cfg.Name == oldName {
                globalSettings.Config[idx] = client.Config
                break
            }
        }
        // Если имя изменилось, обновляем карту Clients
        if oldName != client.Config.Name {
            globalSettings.Clients[client.Config.Name] = client
            delete(globalSettings.Clients, oldName)
        }
        saveConfig()
        logInfo("Edited tunnel '%s' via web interface", tunnelName)
        http.Redirect(w, r, "/", http.StatusFound)
    }
}

func editGlobalHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        data := struct {
            Theme string
            Page  string
        }{
            Theme: getThemeFromCookie(r),
            Page:  "edit_global",
        }
        if err := tmpl.Execute(w, data); err != nil {
            logError("Error executing template: %v", err)
        }
    } else if r.Method == http.MethodPost {
        r.ParseForm()
        maxReconnects, _ := strconv.Atoi(r.FormValue("max_reconnects"))
        for _, client := range globalSettings.Clients {
            client.Config.MaxReconnects = maxReconnects
        }
        // Обновляем globalSettings.Config
        for idx := range globalSettings.Config {
            globalSettings.Config[idx].MaxReconnects = maxReconnects
        }
        saveConfig()
        logInfo("Updated global max reconnections to %d via web interface", maxReconnects)
        http.Redirect(w, r, "/", http.StatusFound)
    }
}

func deleteTunnelHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    tunnelName := r.FormValue("name")
    client, ok := globalSettings.Clients[tunnelName]
    if ok {
        logInfo("Deleting tunnel '%s' via web interface", tunnelName)
        client.Stop()
        delete(globalSettings.Clients, tunnelName)
        for i, cfg := range globalSettings.Config {
            if cfg.Name == tunnelName {
                globalSettings.Config = append(globalSettings.Config[:i], globalSettings.Config[i+1:]...)
                break
            }
        }
        saveConfig()
    } else {
        logWarning("Tunnel '%s' not found", tunnelName)
    }
    http.Redirect(w, r, "/", http.StatusFound)
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
    N := 100
    file, err := os.Open(globalSettings.LogFile)
    if err != nil {
        logError("Failed to read log file: %v", err)
        http.Error(w, "Failed to read log file", http.StatusInternalServerError)
        return
    }
    defer file.Close()

    lines := []string{}
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        lines = append(lines, scanner.Text())
    }

    if len(lines) > N {
        lines = lines[len(lines)-N:]
    }

    data := struct {
        Logs  []string
        Theme string
        Page  string
    }{
        Logs:  lines,
        Theme: getThemeFromCookie(r),
        Page:  "logs",
    }

    if err := tmpl.Execute(w, data); err != nil {
        logError("Error executing template: %v", err)
    }
}

func toggleThemeHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    theme := r.FormValue("theme")
    if theme == "" {
        theme = "light"
    }
    cookie := &http.Cookie{
        Name:    "theme",
        Value:   theme,
        Expires: time.Now().Add(365 * 24 * time.Hour),
    }
    http.SetCookie(w, cookie)
    logInfo("Theme changed to '%s' via web interface", theme)
    http.Redirect(w, r, "/", http.StatusFound)
}

// Обработчик массовых действий
func bulkActionHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }
    err := r.ParseForm()
    if err != nil {
        logError("Ошибка при разборе данных формы: %v", err)
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }
    action := r.FormValue("action")
    selectedTunnels := r.Form["selected_tunnels"]
    if action == "" {
        logWarning("Действие не указано в массовом действии")
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }
    if len(selectedTunnels) == 0 {
        logWarning("Не выбраны туннели для массового действия '%s'", action)
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }
    for _, tunnelName := range selectedTunnels {
        client, ok := globalSettings.Clients[tunnelName]
        if ok {
            switch action {
            case "start_selected":
                logInfo("Запуск выбранного туннеля '%s' через веб-интерфейс", tunnelName)
                go client.Start()
            case "stop_selected":
                logInfo("Остановка выбранного туннеля '%s' через веб-интерфейс", tunnelName)
                client.Stop()
            case "restart_selected":
                logInfo("Перезапуск выбранного туннеля '%s' через веб-интерфейс", tunnelName)
                client.Stop()
                go client.Start()
            case "delete_selected":
                logInfo("Удаление выбранного туннеля '%s' через веб-интерфейс", tunnelName)
                client.Stop()
                delete(globalSettings.Clients, tunnelName)
                for i, cfg := range globalSettings.Config {
                    if cfg.Name == tunnelName {
                        globalSettings.Config = append(globalSettings.Config[:i], globalSettings.Config[i+1:]...)
                        break
                    }
                }
                saveConfig()
            default:
                logWarning("Неизвестное массовое действие: %s", action)
            }
        } else {
            logWarning("Выбранный туннель '%s' не найден", tunnelName)
        }
    }
    http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Вспомогательные функции

func getTunnelList() []*SSHClient {
    tunnels := []*SSHClient{}
    for _, client := range globalSettings.Clients {
        tunnels = append(tunnels, client)
    }

    sort.Slice(tunnels, func(i, j int) bool {
        return tunnels[i].Config.SerialNumber < tunnels[j].Config.SerialNumber
    })

    return tunnels
}

func getActiveTunnelCount() int {
    count := 0
    for _, client := range globalSettings.Clients {
        client.Mutex.Lock()
        if client.Status == "running" {
            count++
        }
        client.Mutex.Unlock()
    }
    return count
}

func getErrorTunnelCount() int {
    count := 0
    for _, client := range globalSettings.Clients {
        client.Mutex.Lock()
        if client.Status == "error" {
            count++
        }
        client.Mutex.Unlock()
    }
    return count
}

func getRestartingTunnelCount() int {
    count := 0
    for _, client := range globalSettings.Clients {
        client.Mutex.Lock()
        if client.Status == "restarting" {
            count++
        }
        client.Mutex.Unlock()
    }
    return count
}

func getGroupedTunnels() map[string][]*SSHClient {
    grouped := make(map[string][]*SSHClient)
    for _, client := range globalSettings.Clients {
        group := client.Config.Group
        if group == "" {
            group = "Default"
        }
        grouped[group] = append(grouped[group], client)
    }

    // Сортируем группы
    sortedGroups := make(map[string][]*SSHClient)
    groupNames := make([]string, 0, len(grouped))
    for group := range grouped {
        groupNames = append(groupNames, group)
    }
    sort.Strings(groupNames)
    for _, group := range groupNames {
        tunnels := grouped[group]
        // Сортируем туннели внутри группы по SerialNumber
        sort.Slice(tunnels, func(i, j int) bool {
            return tunnels[i].Config.SerialNumber < tunnels[j].Config.SerialNumber
        })
        sortedGroups[group] = tunnels
    }

    return sortedGroups
}

func getThemeFromCookie(r *http.Request) string {
    cookie, err := r.Cookie("theme")
    if err != nil {
        return "light"
    }
    return cookie.Value
}

func saveConfig() {
    data, err := json.MarshalIndent(globalSettings.Config, "", "  ")
    if err != nil {
        logError("Error saving configuration: %v", err)
        return
    }

    err = os.WriteFile(globalSettings.ConfigPath, data, 0644)
    if err != nil {
        logError("Error writing config file: %v", err)
    } else {
        logInfo("Configuration saved to '%s'", globalSettings.ConfigPath)
    }
}

// Функции логирования

func logWithLevel(level string, format string, v ...interface{}) {
    message := fmt.Sprintf(format, v...)
    timestamp := time.Now().Format("2006-01-02 15:04:05.000")
    switch strings.ToUpper(level) {
    case "DEBUG":
        if globalSettings.LogLevel == "DEBUG" {
            color.New(color.FgCyan).Printf("%s - DEBUG - %s\n", timestamp, message)
            log.Printf("DEBUG - %s", message)
        }
    case "INFO":
        if globalSettings.LogLevel == "DEBUG" || globalSettings.LogLevel == "INFO" {
            color.New(color.FgGreen).Printf("%s - INFO - %s\n", timestamp, message)
            log.Printf("INFO - %s", message)
        }
    case "WARNING":
        if globalSettings.LogLevel == "DEBUG" || globalSettings.LogLevel == "INFO" || globalSettings.LogLevel == "WARNING" {
            color.New(color.FgYellow).Printf("%s - WARNING - %s\n", timestamp, message)
            log.Printf("WARNING - %s", message)
        }
    case "ERROR":
        color.New(color.FgRed).Printf("%s - ERROR - %s\n", timestamp, message)
        log.Printf("ERROR - %s", message)
    default:
        fmt.Printf("%s - %s - %s\n", timestamp, level, message)
        log.Printf("%s - %s", level, message)
    }
}

func logDebug(format string, v ...interface{}) {
    logWithLevel("DEBUG", format, v...)
}

func logInfo(format string, v ...interface{}) {
    logWithLevel("INFO", format, v...)
}

func logWarning(format string, v ...interface{}) {
    logWithLevel("WARNING", format, v...)
}

func logError(format string, v ...interface{}) {
    logWithLevel("ERROR", format, v...)
}
