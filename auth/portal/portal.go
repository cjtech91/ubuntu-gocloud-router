package portal

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"sync"
	"time"
)

// User represents an authenticated user
type User struct {
	ID          string
	MAC         string
	IP          string
	Username    string
	LoginTime   time.Time
	ExpiryTime  time.Time
	UploadBytes uint64
	DownBytes   uint64
	Active      bool
}

// AuthMethod defines authentication methods
type AuthMethod string

const (
	AuthMethodPassword AuthMethod = "password"
	AuthMethodSMS      AuthMethod = "sms"
	AuthMethodWeChat   AuthMethod = "wechat"
	AuthMethodVoucher  AuthMethod = "voucher"
)

// PortalConfig holds portal configuration
type PortalConfig struct {
	Interface      string
	ListenAddr     string
	SessionTimeout time.Duration
	RedirectURL    string
	AllowedDomains []string // Domains accessible without auth (e.g., payment)
}

// CaptivePortal manages user authentication
type CaptivePortal struct {
	mu       sync.RWMutex
	config   *PortalConfig
	users    map[string]*User // MAC -> User
	sessions map[string]*User // Session ID -> User
	server   *http.Server
}

// NewCaptivePortal creates a new captive portal
func NewCaptivePortal(config *PortalConfig) *CaptivePortal {
	return &CaptivePortal{
		config:   config,
		users:    make(map[string]*User),
		sessions: make(map[string]*User),
	}
}

// Start starts the captive portal HTTP server
func (cp *CaptivePortal) Start() error {
	// Setup firewall rules to redirect HTTP traffic
	if err := cp.setupFirewallRedirect(); err != nil {
		return fmt.Errorf("failed to setup firewall: %w", err)
	}

	// Create HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/", cp.handlePortalPage)
	mux.HandleFunc("/login", cp.handleLogin)
	mux.HandleFunc("/logout", cp.handleLogout)
	mux.HandleFunc("/status", cp.handleStatus)

	cp.server = &http.Server{
		Addr:    cp.config.ListenAddr,
		Handler: mux,
	}

	// Start cleanup goroutine
	go cp.cleanupExpiredSessions()

	// Start HTTP server
	return cp.server.ListenAndServe()
}

// setupFirewallRedirect redirects unauthenticated HTTP traffic to portal
func (cp *CaptivePortal) setupFirewallRedirect() error {
	// Create nat prerouting chain for portal redirect
	cmd := exec.Command("nft", "add", "chain", "ip", "nat", "portal_redirect",
		"{", "type", "nat", "hook", "prerouting", "priority", "0", ";", "}")
	cmd.Run() // Ignore if exists

	// Redirect HTTP traffic to portal (except authenticated users)
	cmd = exec.Command("nft", "add", "rule", "ip", "nat", "portal_redirect",
		"tcp", "dport", "80", "counter", "redirect", "to", ":8080")
	if err := cmd.Run(); err != nil {
		return err
	}

	// Redirect HTTPS traffic for detection
	cmd = exec.Command("nft", "add", "rule", "ip", "nat", "portal_redirect",
		"tcp", "dport", "443", "counter", "redirect", "to", ":8443")
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

// handlePortalPage serves the login page
func (cp *CaptivePortal) handlePortalPage(w http.ResponseWriter, r *http.Request) {
	// Get client MAC and IP
	clientIP := cp.getClientIP(r)
	clientMAC := cp.getMACFromIP(clientIP)

	// Check if already authenticated
	cp.mu.RLock()
	user, exists := cp.users[clientMAC]
	cp.mu.RUnlock()

	if exists && user.Active && time.Now().Before(user.ExpiryTime) {
		// Already authenticated, redirect
		http.Redirect(w, r, cp.config.RedirectURL, http.StatusFound)
		return
	}

	// Serve login page
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>WiFi Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial; text-align: center; padding: 50px; }
        .login-box { max-width: 400px; margin: 0 auto; padding: 20px; border: 1px solid #ccc; }
        input { width: 100%; padding: 10px; margin: 10px 0; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Welcome to WiFi Network</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

// handleLogin processes login requests
func (cp *CaptivePortal) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Validate credentials (implement your auth logic)
	if !cp.validateCredentials(username, password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Get client info
	clientIP := cp.getClientIP(r)
	clientMAC := cp.getMACFromIP(clientIP)

	// Create session
	sessionID := cp.generateSessionID()
	user := &User{
		ID:         sessionID,
		MAC:        clientMAC,
		IP:         clientIP,
		Username:   username,
		LoginTime:  time.Now(),
		ExpiryTime: time.Now().Add(cp.config.SessionTimeout),
		Active:     true,
	}

	cp.mu.Lock()
	cp.users[clientMAC] = user
	cp.sessions[sessionID] = user
	cp.mu.Unlock()

	// Allow traffic from this user
	if err := cp.allowUserTraffic(user); err != nil {
		http.Error(w, "Failed to authorize", http.StatusInternalServerError)
		return
	}

	// Redirect to success page or original URL
	http.Redirect(w, r, cp.config.RedirectURL, http.StatusFound)
}

// handleLogout logs out a user
func (cp *CaptivePortal) handleLogout(w http.ResponseWriter, r *http.Request) {
	clientIP := cp.getClientIP(r)
	clientMAC := cp.getMACFromIP(clientIP)

	cp.mu.Lock()
	user, exists := cp.users[clientMAC]
	if exists {
		user.Active = false
		cp.blockUserTraffic(user)
		delete(cp.users, clientMAC)
		delete(cp.sessions, user.ID)
	}
	cp.mu.Unlock()

	fmt.Fprintf(w, "Logged out successfully")
}

// handleStatus returns user session status
func (cp *CaptivePortal) handleStatus(w http.ResponseWriter, r *http.Request) {
	clientIP := cp.getClientIP(r)
	clientMAC := cp.getMACFromIP(clientIP)

	cp.mu.RLock()
	user, exists := cp.users[clientMAC]
	cp.mu.RUnlock()

	if !exists || !user.Active {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Not authenticated")
		return
	}

	remaining := user.ExpiryTime.Sub(time.Now())
	fmt.Fprintf(w, "Authenticated as %s, %v remaining", user.Username, remaining)
}

// allowUserTraffic adds firewall rules to allow authenticated user
func (cp *CaptivePortal) allowUserTraffic(user *User) error {
	// Add rule to allow traffic from authenticated MAC
	cmd := exec.Command("nft", "insert", "rule", "ip", "filter", "FORWARD",
		"ether", "saddr", user.MAC, "counter", "accept")
	if err := cmd.Run(); err != nil {
		return err
	}

	// Mark user as authenticated in connection tracking
	cmd = exec.Command("nft", "add", "rule", "ip", "mangle", "PREROUTING",
		"ip", "saddr", user.IP, "counter", "mark", "set", "0x1")
	
	return cmd.Run()
}

// blockUserTraffic removes firewall rules for user
func (cp *CaptivePortal) blockUserTraffic(user *User) error {
	// Remove allow rules
	cmd := exec.Command("nft", "delete", "rule", "ip", "filter", "FORWARD",
		"ether", "saddr", user.MAC)
	cmd.Run() // Ignore errors

	cmd = exec.Command("nft", "delete", "rule", "ip", "mangle", "PREROUTING",
		"ip", "saddr", user.IP)
	cmd.Run()

	return nil
}

// validateCredentials validates user credentials
func (cp *CaptivePortal) validateCredentials(username, password string) bool {
	// Implement actual validation against database/RADIUS/LDAP
	// For now, simple demo validation
	return username != "" && password != ""
}

// getClientIP extracts client IP from request
func (cp *CaptivePortal) getClientIP(r *http.Request) string {
	// Try X-Forwarded-For first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	
	// Fall back to RemoteAddr
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// getMACFromIP gets MAC address from IP using ARP
func (cp *CaptivePortal) getMACFromIP(ip string) string {
	cmd := exec.Command("ip", "neigh", "show", ip)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Parse ARP output to extract MAC
	// Format: "192.168.1.100 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
	// Simplified parsing - would need more robust implementation
	return string(output)
}

// generateSessionID generates a random session ID
func (cp *CaptivePortal) generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// cleanupExpiredSessions removes expired sessions
func (cp *CaptivePortal) cleanupExpiredSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		cp.mu.Lock()
		
		for mac, user := range cp.users {
			if now.After(user.ExpiryTime) {
				user.Active = false
				cp.blockUserTraffic(user)
				delete(cp.users, mac)
				delete(cp.sessions, user.ID)
			}
		}
		
		cp.mu.Unlock()
	}
}

// GetActiveUsers returns list of active users
func (cp *CaptivePortal) GetActiveUsers() []*User {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	users := make([]*User, 0, len(cp.users))
	for _, user := range cp.users {
		if user.Active {
			users = append(users, user)
		}
	}

	return users
}
