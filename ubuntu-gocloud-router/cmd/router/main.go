package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yourusername/ubuntu-gocloud-router/core/routing"
	"github.com/yourusername/ubuntu-gocloud-router/core/vlan"
	"github.com/yourusername/ubuntu-gocloud-router/traffic/qos"
	"github.com/yourusername/ubuntu-gocloud-router/security/firewall"
	"github.com/yourusername/ubuntu-gocloud-router/auth/portal"
	"github.com/yourusername/ubuntu-gocloud-router/api"
)

func main() {
	configFile := flag.String("config", "/etc/gocloud/config.yaml", "Configuration file path")
	flag.Parse()

	log.Printf("Starting GoCloud Router...")
	log.Printf("Config file: %s", *configFile)

	// Initialize routing manager
	routingMgr := routing.NewRoutingManager()
	
	// Enable IP forwarding
	if err := routing.EnableIPForwarding(); err != nil {
		log.Fatalf("Failed to enable IP forwarding: %v", err)
	}
	log.Println("✓ IP forwarding enabled")

	// Initialize VLAN manager
	vlanMgr := vlan.NewVLANManager()
	log.Println("✓ VLAN manager initialized")

	// Initialize QoS manager
	qosMgr := qos.NewQoSManager("eth0", "100mbit")
	if err := qosMgr.Initialize(); err != nil {
		log.Printf("Warning: Failed to initialize QoS: %v", err)
	} else {
		log.Println("✓ QoS manager initialized")
	}

	// Initialize firewall
	firewallMgr := firewall.NewFirewallManager()
	if err := firewallMgr.Initialize(); err != nil {
		log.Fatalf("Failed to initialize firewall: %v", err)
	}
	log.Println("✓ Firewall initialized")

	// Enable security features
	if err := firewallMgr.EnableDoSProtection(); err != nil {
		log.Printf("Warning: Failed to enable DoS protection: %v", err)
	} else {
		log.Println("✓ DoS protection enabled")
	}

	// Example: Add WAN interfaces
	wan1 := &routing.WANInterface{
		Name:    "eth0",
		Metric:  100,
		Weight:  10,
		Enabled: true,
		Status:  "active",
	}

	if err := routingMgr.AddWAN(wan1); err != nil {
		log.Printf("Warning: Failed to add WAN interface eth0: %v", err)
	} else {
		log.Println("✓ WAN interface eth0 configured")
	}

	// Setup NAT
	if err := routing.SetupNAT([]string{"eth0"}, "192.168.1.0/24"); err != nil {
		log.Printf("Warning: Failed to setup NAT: %v", err)
	} else {
		log.Println("✓ NAT configured")
	}

	// Initialize captive portal
	portalConfig := &portal.PortalConfig{
		Interface:      "eth2",
		ListenAddr:     ":8080",
		SessionTimeout: 24 * time.Hour,
		RedirectURL:    "https://www.google.com",
		AllowedDomains: []string{"captive.apple.com"},
	}
	
	captivePortal := portal.NewCaptivePortal(portalConfig)
	go func() {
		log.Println("✓ Starting captive portal on :8080")
		if err := captivePortal.Start(); err != nil {
			log.Printf("Captive portal error: %v", err)
		}
	}()

	// Start API server
	apiServer := api.NewServer(":8443")
	go func() {
		log.Println("✓ Starting API server on :8443")
		if err := apiServer.Start(); err != nil {
			log.Printf("API server error: %v", err)
		}
	}()

	// Start WAN monitoring
	go monitorWANs(routingMgr)

	log.Println("===================================")
	log.Println("GoCloud Router is running")
	log.Println("API: http://localhost:8443")
	log.Println("Portal: http://localhost:8080")
	log.Println("===================================")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	
	// Cleanup
	// Add cleanup logic here
	
	log.Println("Shutdown complete")
}

// monitorWANs periodically checks WAN connectivity
func monitorWANs(rm *routing.RoutingManager) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		wans := rm.GetWANs()
		for name, wan := range wans {
			if !wan.Enabled {
				continue
			}

			// Check connectivity
			if rm.CheckWANStatus(wan) {
				if wan.Status != "active" {
					log.Printf("WAN %s is back online", name)
					rm.EnableWAN(name)
				}
			} else {
				if wan.Status == "active" {
					log.Printf("WAN %s failed connectivity check", name)
					rm.DisableWAN(name)
				}
			}
		}
	}
}
