package routing

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
)

// WANInterface represents a WAN connection
type WANInterface struct {
	Name      string
	IP        net.IP
	Gateway   net.IP
	Metric    int
	Weight    int
	Status    string
	RxBytes   uint64
	TxBytes   uint64
	Enabled   bool
}

// Route represents a routing table entry
type Route struct {
	Destination *net.IPNet
	Gateway     net.IP
	Interface   string
	Metric      int
	Table       int
}

// RoutingManager manages multi-WAN routing and failover
type RoutingManager struct {
	mu         sync.RWMutex
	wans       map[string]*WANInterface
	routes     []Route
	tables     map[string]int
	nextTable  int
}

// NewRoutingManager creates a new routing manager
func NewRoutingManager() *RoutingManager {
	return &RoutingManager{
		wans:      make(map[string]*WANInterface),
		routes:    make([]Route, 0),
		tables:    make(map[string]int),
		nextTable: 100,
	}
}

// AddWAN adds a WAN interface
func (rm *RoutingManager) AddWAN(wan *WANInterface) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Assign routing table
	if _, exists := rm.tables[wan.Name]; !exists {
		rm.tables[wan.Name] = rm.nextTable
		rm.nextTable++
	}

	rm.wans[wan.Name] = wan

	// Configure interface
	if err := rm.configureInterface(wan); err != nil {
		return fmt.Errorf("failed to configure interface %s: %w", wan.Name, err)
	}

	// Setup routing table
	if err := rm.setupRoutingTable(wan); err != nil {
		return fmt.Errorf("failed to setup routing table for %s: %w", wan.Name, err)
	}

	// Setup routing rules
	if err := rm.setupRoutingRules(wan); err != nil {
		return fmt.Errorf("failed to setup routing rules for %s: %w", wan.Name, err)
	}

	return nil
}

// configureInterface configures the network interface
func (rm *RoutingManager) configureInterface(wan *WANInterface) error {
	// Bring interface up
	cmd := exec.Command("ip", "link", "set", wan.Name, "up")
	if err := cmd.Run(); err != nil {
		return err
	}

	// Set IP address if provided
	if wan.IP != nil {
		cidr := fmt.Sprintf("%s/24", wan.IP.String())
		cmd = exec.Command("ip", "addr", "add", cidr, "dev", wan.Name)
		cmd.Run() // Ignore error if IP already exists
	}

	return nil
}

// setupRoutingTable creates a routing table for the WAN interface
func (rm *RoutingManager) setupRoutingTable(wan *WANInterface) error {
	tableID := rm.tables[wan.Name]

	// Add default route in custom table
	if wan.Gateway != nil {
		cmd := exec.Command("ip", "route", "add", "default",
			"via", wan.Gateway.String(),
			"dev", wan.Name,
			"table", fmt.Sprintf("%d", tableID),
			"metric", fmt.Sprintf("%d", wan.Metric))
		if err := cmd.Run(); err != nil {
			// Ignore if route already exists
			if !strings.Contains(err.Error(), "File exists") {
				return err
			}
		}
	}

	return nil
}

// setupRoutingRules creates policy routing rules
func (rm *RoutingManager) setupRoutingRules(wan *WANInterface) error {
	tableID := rm.tables[wan.Name]

	// Add rule to use this table for traffic from this interface's IP
	if wan.IP != nil {
		cmd := exec.Command("ip", "rule", "add",
			"from", wan.IP.String(),
			"table", fmt.Sprintf("%d", tableID),
			"priority", fmt.Sprintf("%d", 100+tableID))
		cmd.Run() // Ignore error if rule already exists
	}

	return nil
}

// SetupLoadBalancing configures multi-WAN load balancing
func (rm *RoutingManager) SetupLoadBalancing() error {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Build nexthop list for load balancing
	nexthops := make([]string, 0)
	for _, wan := range rm.wans {
		if !wan.Enabled || wan.Gateway == nil {
			continue
		}
		nexthop := fmt.Sprintf("nexthop via %s dev %s weight %d",
			wan.Gateway.String(), wan.Name, wan.Weight)
		nexthops.append(nexthop)
	}

	if len(nexthops) == 0 {
		return fmt.Errorf("no active WAN interfaces for load balancing")
	}

	// Delete existing default route
	exec.Command("ip", "route", "del", "default").Run()

	// Add multi-path default route
	args := []string{"route", "add", "default"}
	args = append(args, strings.Join(nexthops, " "))
	cmd := exec.Command("ip", args...)
	
	return cmd.Run()
}

// CheckWANStatus monitors WAN connectivity
func (rm *RoutingManager) CheckWANStatus(wan *WANInterface) bool {
	// Ping gateway
	if wan.Gateway != nil {
		cmd := exec.Command("ping", "-c", "1", "-W", "2", "-I", wan.Name, wan.Gateway.String())
		if err := cmd.Run(); err != nil {
			return false
		}
	}

	// Ping external host (8.8.8.8)
	cmd := exec.Command("ping", "-c", "1", "-W", "2", "-I", wan.Name, "8.8.8.8")
	return cmd.Run() == nil
}

// EnableWAN enables a WAN interface
func (rm *RoutingManager) EnableWAN(name string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	wan, exists := rm.wans[name]
	if !exists {
		return fmt.Errorf("WAN interface %s not found", name)
	}

	wan.Enabled = true
	wan.Status = "active"

	return rm.SetupLoadBalancing()
}

// DisableWAN disables a WAN interface (failover)
func (rm *RoutingManager) DisableWAN(name string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	wan, exists := rm.wans[name]
	if !exists {
		return fmt.Errorf("WAN interface %s not found", name)
	}

	wan.Enabled = false
	wan.Status = "failed"

	return rm.SetupLoadBalancing()
}

// GetWANs returns all WAN interfaces
func (rm *RoutingManager) GetWANs() map[string]*WANInterface {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	result := make(map[string]*WANInterface)
	for k, v := range rm.wans {
		result[k] = v
	}
	return result
}

// AddStaticRoute adds a static route
func (rm *RoutingManager) AddStaticRoute(route Route) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	args := []string{"route", "add"}
	args = append(args, route.Destination.String())
	
	if route.Gateway != nil {
		args = append(args, "via", route.Gateway.String())
	}
	
	if route.Interface != "" {
		args = append(args, "dev", route.Interface)
	}
	
	if route.Metric > 0 {
		args = append(args, "metric", fmt.Sprintf("%d", route.Metric))
	}
	
	if route.Table > 0 {
		args = append(args, "table", fmt.Sprintf("%d", route.Table))
	}

	cmd := exec.Command("ip", args...)
	if err := cmd.Run(); err != nil {
		return err
	}

	rm.routes = append(rm.routes, route)
	return nil
}

// EnableIPForwarding enables IP forwarding
func EnableIPForwarding() error {
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if err := cmd.Run(); err != nil {
		return err
	}
	
	cmd = exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
	return cmd.Run()
}

// SetupNAT configures NAT for WAN interfaces
func SetupNAT(wanInterfaces []string, lanSubnet string) error {
	for _, wan := range wanInterfaces {
		// Using nftables for NAT
		cmd := exec.Command("nft", "add", "rule", "ip", "nat", "postrouting",
			"oifname", wan, "ip", "saddr", lanSubnet, "masquerade")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to setup NAT for %s: %w", wan, err)
		}
	}
	return nil
}
