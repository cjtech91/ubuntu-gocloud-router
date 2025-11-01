package qos

import (
	"fmt"
	"os/exec"
	"sync"
)

// TrafficClass represents a traffic classification
type TrafficClass struct {
	ID          int
	Name        string
	Priority    int
	MinRate     string // e.g., "1mbit"
	MaxRate     string // e.g., "10mbit"
	BurstRate   string
	MatchRules  []MatchRule
}

// MatchRule defines how to match traffic
type MatchRule struct {
	Protocol    string // tcp, udp, icmp
	SrcIP       string
	DstIP       string
	SrcPort     string
	DstPort     string
	Mark        int
	Application string // for DPI
}

// BandwidthLimit represents per-user/IP bandwidth limits
type BandwidthLimit struct {
	IP        string
	UploadMax string
	DownMax   string
	Priority  int
}

// QoSManager manages traffic shaping and QoS
type QoSManager struct {
	mu            sync.RWMutex
	interface     string
	classes       map[int]*TrafficClass
	limits        map[string]*BandwidthLimit
	totalBandwidth string
	nextClassID   int
}

// NewQoSManager creates a new QoS manager
func NewQoSManager(iface string, totalBandwidth string) *QoSManager {
	return &QoSManager{
		interface:      iface,
		classes:        make(map[int]*TrafficClass),
		limits:         make(map[string]*BandwidthLimit),
		totalBandwidth: totalBandwidth,
		nextClassID:    100,
	}
}

// Initialize sets up the root qdisc
func (qm *QoSManager) Initialize() error {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	// Delete existing qdisc
	exec.Command("tc", "qdisc", "del", "dev", qm.interface, "root").Run()

	// Create root HTB qdisc
	cmd := exec.Command("tc", "qdisc", "add", "dev", qm.interface,
		"root", "handle", "1:", "htb", "default", "99")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create root qdisc: %w", err)
	}

	// Create root class
	cmd = exec.Command("tc", "class", "add", "dev", qm.interface,
		"parent", "1:", "classid", "1:1", "htb",
		"rate", qm.totalBandwidth)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create root class: %w", err)
	}

	// Create default class for unclassified traffic
	cmd = exec.Command("tc", "class", "add", "dev", qm.interface,
		"parent", "1:1", "classid", "1:99", "htb",
		"rate", "1mbit", "ceil", qm.totalBandwidth, "prio", "7")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create default class: %w", err)
	}

	// Add fq_codel qdisc to default class for better latency
	cmd = exec.Command("tc", "qdisc", "add", "dev", qm.interface,
		"parent", "1:99", "fq_codel")
	return cmd.Run()
}

// AddTrafficClass creates a new traffic class with HTB
func (qm *QoSManager) AddTrafficClass(tc *TrafficClass) error {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	if tc.ID == 0 {
		tc.ID = qm.nextClassID
		qm.nextClassID++
	}

	classID := fmt.Sprintf("1:%d", tc.ID)

	// Create HTB class
	args := []string{"class", "add", "dev", qm.interface,
		"parent", "1:1", "classid", classID, "htb",
		"rate", tc.MinRate, "ceil", tc.MaxRate,
		"prio", fmt.Sprintf("%d", tc.Priority)}

	if tc.BurstRate != "" {
		args = append(args, "burst", tc.BurstRate)
	}

	cmd := exec.Command("tc", args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create traffic class: %w", err)
	}

	// Add fq_codel qdisc for fair queuing
	cmd = exec.Command("tc", "qdisc", "add", "dev", qm.interface,
		"parent", classID, "fq_codel")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add qdisc to class: %w", err)
	}

	// Add filters for matching rules
	for i, rule := range tc.MatchRules {
		if err := qm.addFilter(tc.ID, i+1, rule); err != nil {
			return fmt.Errorf("failed to add filter: %w", err)
		}
	}

	qm.classes[tc.ID] = tc
	return nil
}

// addFilter adds a tc filter for traffic matching
func (qm *QoSManager) addFilter(classID, filterID int, rule MatchRule) error {
	handleID := classID*100 + filterID
	flowID := fmt.Sprintf("1:%d", classID)

	args := []string{"filter", "add", "dev", qm.interface,
		"protocol", "ip", "parent", "1:", "prio", "1",
		"handle", fmt.Sprintf("%d", handleID), "fw", "flowid", flowID}

	// For marked packets
	if rule.Mark > 0 {
		cmd := exec.Command("tc", args...)
		if err := cmd.Run(); err != nil {
			return err
		}

		// Mark packets using iptables/nftables
		return qm.addMarkRule(rule)
	}

	// For IP-based matching using u32 filter
	if rule.SrcIP != "" || rule.DstIP != "" {
		args = []string{"filter", "add", "dev", qm.interface,
			"protocol", "ip", "parent", "1:", "prio", "1", "u32"}

		if rule.SrcIP != "" {
			args = append(args, "match", "ip", "src", rule.SrcIP)
		}
		if rule.DstIP != "" {
			args = append(args, "match", "ip", "dst", rule.DstIP)
		}

		args = append(args, "flowid", flowID)
		cmd := exec.Command("tc", args...)
		return cmd.Run()
	}

	return nil
}

// addMarkRule marks packets using nftables
func (qm *QoSManager) addMarkRule(rule MatchRule) error {
	args := []string{"add", "rule", "ip", "mangle", "PREROUTING"}

	if rule.SrcIP != "" {
		args = append(args, "ip", "saddr", rule.SrcIP)
	}
	if rule.DstIP != "" {
		args = append(args, "ip", "daddr", rule.DstIP)
	}
	if rule.Protocol != "" {
		args = append(args, "ip", "protocol", rule.Protocol)
	}
	if rule.SrcPort != "" {
		args = append(args, rule.Protocol, "sport", rule.SrcPort)
	}
	if rule.DstPort != "" {
		args = append(args, rule.Protocol, "dport", rule.DstPort)
	}

	args = append(args, "counter", "mark", "set", fmt.Sprintf("%d", rule.Mark))

	cmd := exec.Command("nft", args...)
	return cmd.Run()
}

// SetBandwidthLimit sets per-IP bandwidth limits
func (qm *QoSManager) SetBandwidthLimit(limit *BandwidthLimit) error {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	// Create upload limit (egress)
	uploadClass := &TrafficClass{
		Name:    fmt.Sprintf("limit-upload-%s", limit.IP),
		MinRate: "128kbit",
		MaxRate: limit.UploadMax,
		Priority: limit.Priority,
		MatchRules: []MatchRule{
			{SrcIP: limit.IP},
		},
	}

	if err := qm.AddTrafficClass(uploadClass); err != nil {
		return fmt.Errorf("failed to set upload limit: %w", err)
	}

	// Create download limit (ingress) using IFB
	if err := qm.setupIngressLimit(limit); err != nil {
		return fmt.Errorf("failed to set download limit: %w", err)
	}

	qm.limits[limit.IP] = limit
	return nil
}

// setupIngressLimit sets up download limits using IFB (Intermediate Functional Block)
func (qm *QoSManager) setupIngressLimit(limit *BandwidthLimit) error {
	ifbDev := "ifb0"

	// Load IFB module
	exec.Command("modprobe", "ifb").Run()

	// Bring up IFB device
	exec.Command("ip", "link", "set", ifbDev, "up").Run()

	// Redirect ingress to IFB
	cmd := exec.Command("tc", "qdisc", "add", "dev", qm.interface,
		"handle", "ffff:", "ingress")
	cmd.Run() // Ignore if already exists

	cmd = exec.Command("tc", "filter", "add", "dev", qm.interface,
		"parent", "ffff:", "protocol", "ip", "u32",
		"match", "u32", "0", "0",
		"action", "mirred", "egress", "redirect", "dev", ifbDev)
	cmd.Run()

	// Setup HTB on IFB for ingress shaping
	exec.Command("tc", "qdisc", "del", "dev", ifbDev, "root").Run()
	cmd = exec.Command("tc", "qdisc", "add", "dev", ifbDev,
		"root", "handle", "1:", "htb")
	if err := cmd.Run(); err != nil {
		return err
	}

	// Add class for this IP's download limit
	classID := fmt.Sprintf("1:%d", len(qm.limits)+100)
	cmd = exec.Command("tc", "class", "add", "dev", ifbDev,
		"parent", "1:", "classid", classID, "htb",
		"rate", limit.DownMax)
	if err := cmd.Run(); err != nil {
		return err
	}

	// Add filter to match destination IP
	cmd = exec.Command("tc", "filter", "add", "dev", ifbDev,
		"protocol", "ip", "parent", "1:", "prio", "1", "u32",
		"match", "ip", "dst", limit.IP,
		"flowid", classID)

	return cmd.Run()
}

// GetStatistics retrieves traffic statistics for a class
func (qm *QoSManager) GetStatistics(classID int) (map[string]string, error) {
	classIDStr := fmt.Sprintf("1:%d", classID)
	
	cmd := exec.Command("tc", "-s", "class", "show", "dev", qm.interface,
		"classid", classIDStr)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse output (simplified - would need proper parsing)
	stats := make(map[string]string)
	stats["output"] = string(output)
	
	return stats, nil
}

// RemoveTrafficClass removes a traffic class
func (qm *QoSManager) RemoveTrafficClass(classID int) error {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	classIDStr := fmt.Sprintf("1:%d", classID)

	// Delete class
	cmd := exec.Command("tc", "class", "del", "dev", qm.interface,
		"classid", classIDStr)
	if err := cmd.Run(); err != nil {
		return err
	}

	delete(qm.classes, classID)
	return nil
}

// Reset clears all QoS configuration
func (qm *QoSManager) Reset() error {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	// Delete root qdisc (removes all classes and filters)
	cmd := exec.Command("tc", "qdisc", "del", "dev", qm.interface, "root")
	if err := cmd.Run(); err != nil {
		return err
	}

	qm.classes = make(map[int]*TrafficClass)
	qm.limits = make(map[string]*BandwidthLimit)
	qm.nextClassID = 100

	return nil
}
