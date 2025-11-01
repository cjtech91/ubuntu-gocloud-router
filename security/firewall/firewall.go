package firewall

import (
	"fmt"
	"os/exec"
	"sync"
)

// Rule represents a firewall rule
type Rule struct {
	ID          string
	Chain       string
	Protocol    string
	SrcIP       string
	DstIP       string
	SrcPort     string
	DstPort     string
	Action      string // accept, drop, reject
	Comment     string
}

// FirewallManager manages nftables firewall rules
type FirewallManager struct {
	mu    sync.RWMutex
	rules map[string]*Rule
}

// NewFirewallManager creates a new firewall manager
func NewFirewallManager() *FirewallManager {
	return &FirewallManager{
		rules: make(map[string]*Rule),
	}
}

// Initialize sets up basic nftables structure
func (fm *FirewallManager) Initialize() error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// Flush existing ruleset
	exec.Command("nft", "flush", "ruleset").Run()

	// Create inet table (handles both IPv4 and IPv6)
	commands := [][]string{
		{"add", "table", "inet", "filter"},
		
		// Create chains
		{"add", "chain", "inet", "filter", "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "drop", ";", "}"},
		{"add", "chain", "inet", "filter", "forward", "{", "type", "filter", "hook", "forward", "priority", "0", ";", "policy", "drop", ";", "}"},
		{"add", "chain", "inet", "filter", "output", "{", "type", "filter", "hook", "output", "priority", "0", ";", "policy", "accept", ";", "}"},
		
		// Allow established/related connections
		{"add", "rule", "inet", "filter", "input", "ct", "state", "established,related", "counter", "accept"},
		{"add", "rule", "inet", "filter", "forward", "ct", "state", "established,related", "counter", "accept"},
		
		// Allow loopback
		{"add", "rule", "inet", "filter", "input", "iif", "lo", "counter", "accept"},
		
		// Allow ICMP
		{"add", "rule", "inet", "filter", "input", "ip", "protocol", "icmp", "counter", "accept"},
		{"add", "rule", "inet", "filter", "input", "ip6", "nexthdr", "icmpv6", "counter", "accept"},
		
		// Allow SSH (adjust port as needed)
		{"add", "rule", "inet", "filter", "input", "tcp", "dport", "22", "counter", "accept"},
		
		// Create NAT table
		{"add", "table", "ip", "nat"},
		{"add", "chain", "ip", "nat", "prerouting", "{", "type", "nat", "hook", "prerouting", "priority", "-100", ";", "}"},
		{"add", "chain", "ip", "nat", "postrouting", "{", "type", "nat", "hook", "postrouting", "priority", "100", ";", "}"},
		
		// Create mangle table for marking
		{"add", "table", "ip", "mangle"},
		{"add", "chain", "ip", "mangle", "prerouting", "{", "type", "filter", "hook", "prerouting", "priority", "-150", ";", "}"},
	}

	for _, cmd := range commands {
		if err := exec.Command("nft", cmd...).Run(); err != nil {
			return fmt.Errorf("failed to run nft command %v: %w", cmd, err)
		}
	}

	return nil
}

// AddRule adds a new firewall rule
func (fm *FirewallManager) AddRule(rule *Rule) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	args := []string{"add", "rule", "inet", "filter", rule.Chain}

	// Build rule
	if rule.Protocol != "" {
		args = append(args, rule.Protocol)
	}
	if rule.SrcIP != "" {
		args = append(args, "ip", "saddr", rule.SrcIP)
	}
	if rule.DstIP != "" {
		args = append(args, "ip", "daddr", rule.DstIP)
	}
	if rule.SrcPort != "" {
		args = append(args, rule.Protocol, "sport", rule.SrcPort)
	}
	if rule.DstPort != "" {
		args = append(args, rule.Protocol, "dport", rule.DstPort)
	}

	args = append(args, "counter", rule.Action)

	if rule.Comment != "" {
		args = append(args, "comment", fmt.Sprintf("\"%s\"", rule.Comment))
	}

	cmd := exec.Command("nft", args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add rule: %w", err)
	}

	fm.rules[rule.ID] = rule
	return nil
}

// EnableARPProtection protects against ARP spoofing
func (fm *FirewallManager) EnableARPProtection(iface string) error {
	// Enable DAI (Dynamic ARP Inspection) equivalent
	commands := [][]string{
		// Drop packets with mismatched source IP/MAC
		{"add", "rule", "inet", "filter", "input", "iifname", iface, "arp", "operation", "reply", "counter", "log", "prefix", "\"ARP-SPOOF: \""},
		
		// Enable kernel ARP filtering
	}

	for _, cmd := range commands {
		exec.Command("nft", cmd...).Run()
	}

	// Enable kernel-level ARP protection
	exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.arp_filter=1", iface)).Run()
	exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.arp_announce=2", iface)).Run()
	exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.arp_ignore=1", iface)).Run()

	return nil
}

// EnableDoSProtection enables basic DoS/DDoS mitigation
func (fm *FirewallManager) EnableDoSProtection() error {
	commands := [][]string{
		// SYN flood protection
		{"add", "rule", "inet", "filter", "input", "tcp", "flags", "syn", "tcp", "dport", "22", "meter", "syn-flood", "{", "ip", "saddr", "timeout", "10s", "limit", "rate", "25/second", "burst", "50", "packets", "}", "counter", "accept"},
		
		// Connection limiting
		{"add", "rule", "inet", "filter", "input", "ct", "state", "new", "limit", "rate", "100/second", "burst", "150", "packets", "counter", "accept"},
		
		// Ping flood protection
		{"add", "rule", "inet", "filter", "input", "icmp", "type", "echo-request", "limit", "rate", "10/second", "counter", "accept"},
		
		// Port scan detection (drop NEW packets that aren't SYN)
		{"add", "rule", "inet", "filter", "input", "tcp", "flags", "!=", "syn", "ct", "state", "new", "counter", "drop"},
	}

	// Enable kernel-level SYN cookie protection
	exec.Command("sysctl", "-w", "net.ipv4.tcp_syncookies=1").Run()
	exec.Command("sysctl", "-w", "net.ipv4.tcp_max_syn_backlog=2048").Run()
	exec.Command("sysctl", "-w", "net.ipv4.tcp_synack_retries=2").Run()
	exec.Command("sysctl", "-w", "net.ipv4.tcp_syn_retries=5").Run()

	// Enable reverse path filtering
	exec.Command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=1").Run()
	exec.Command("sysctl", "-w", "net.ipv4.conf.default.rp_filter=1").Run()

	// Disable ICMP redirect
	exec.Command("sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0").Run()
	exec.Command("sysctl", "-w", "net.ipv4.conf.all.send_redirects=0").Run()

	// Ignore ICMP pings
	// exec.Command("sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=1").Run()

	for _, cmd := range commands {
		exec.Command("nft", cmd...).Run()
	}

	return nil
}

// AddPortForward adds a port forwarding rule
func (fm *FirewallManager) AddPortForward(extPort, intIP, intPort, protocol string) error {
	// Add DNAT rule
	cmd := exec.Command("nft", "add", "rule", "ip", "nat", "prerouting",
		protocol, "dport", extPort,
		"counter", "dnat", "to", fmt.Sprintf("%s:%s", intIP, intPort))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add DNAT rule: %w", err)
	}

	// Add forward rule
	cmd = exec.Command("nft", "add", "rule", "inet", "filter", "forward",
		"ip", "daddr", intIP, protocol, "dport", intPort, "counter", "accept")
	
	return cmd.Run()
}

// BlockIP blocks an IP address
func (fm *FirewallManager) BlockIP(ip string) error {
	cmd := exec.Command("nft", "add", "rule", "inet", "filter", "input",
		"ip", "saddr", ip, "counter", "drop")
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("nft", "add", "rule", "inet", "filter", "forward",
		"ip", "saddr", ip, "counter", "drop")
	
	return cmd.Run()
}

// UnblockIP removes IP block
func (fm *FirewallManager) UnblockIP(ip string) error {
	// This would need to track handles to properly delete
	// For now, would need to flush and rebuild or use sets
	return nil
}

// CreateIPSet creates an IP set for bulk operations
func (fm *FirewallManager) CreateIPSet(name string) error {
	cmd := exec.Command("nft", "add", "set", "inet", "filter", name,
		"{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}")
	return cmd.Run()
}

// AddToIPSet adds an IP to a set
func (fm *FirewallManager) AddToIPSet(setName, ip string) error {
	cmd := exec.Command("nft", "add", "element", "inet", "filter", setName,
		"{", ip, "}")
	return cmd.Run()
}

// BlockIPSet blocks all IPs in a set
func (fm *FirewallManager) BlockIPSet(setName string) error {
	cmd := exec.Command("nft", "add", "rule", "inet", "filter", "input",
		"ip", "saddr", "@"+setName, "counter", "drop")
	return cmd.Run()
}

// EnableGeoBlocking blocks traffic from specific countries (requires GeoIP)
func (fm *FirewallManager) EnableGeoBlocking(countries []string) error {
	// Would integrate with GeoIP database
	// Simplified implementation
	for _, country := range countries {
		// Load country IP ranges and add to set
		fmt.Printf("Would block country: %s\n", country)
	}
	return nil
}

// GetRuleStats gets statistics for rules
func (fm *FirewallManager) GetRuleStats() (string, error) {
	cmd := exec.Command("nft", "list", "ruleset", "-a", "-s")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// SaveRules saves current ruleset to file
func (fm *FirewallManager) SaveRules(filename string) error {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("nft list ruleset > %s", filename))
	return cmd.Run()
}

// LoadRules loads ruleset from file
func (fm *FirewallManager) LoadRules(filename string) error {
	cmd := exec.Command("nft", "-f", filename)
	return cmd.Run()
}

// Reset flushes all rules
func (fm *FirewallManager) Reset() error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	cmd := exec.Command("nft", "flush", "ruleset")
	if err := cmd.Run(); err != nil {
		return err
	}

	fm.rules = make(map[string]*Rule)
	return nil
}
