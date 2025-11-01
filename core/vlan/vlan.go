package vlan

import (
	"fmt"
	"os/exec"
	"sync"
)

// VLAN represents a VLAN configuration
type VLAN struct {
	ID          int
	Name        string
	ParentIface string
	IP          string
	Subnet      string
	DHCPEnabled bool
	DHCPStart   string
	DHCPEnd     string
	Isolated    bool // Guest network isolation
}

// VLANManager manages VLAN configurations
type VLANManager struct {
	mu    sync.RWMutex
	vlans map[int]*VLAN
}

// NewVLANManager creates a new VLAN manager
func NewVLANManager() *VLANManager {
	return &VLANManager{
		vlans: make(map[int]*VLAN),
	}
}

// CreateVLAN creates a new VLAN interface
func (vm *VLANManager) CreateVLAN(vlan *VLAN) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Check if VLAN already exists
	if _, exists := vm.vlans[vlan.ID]; exists {
		return fmt.Errorf("VLAN %d already exists", vlan.ID)
	}

	// Create VLAN interface
	ifaceName := fmt.Sprintf("%s.%d", vlan.ParentIface, vlan.ID)
	
	// Add VLAN interface using ip link
	cmd := exec.Command("ip", "link", "add", "link", vlan.ParentIface,
		"name", ifaceName, "type", "vlan", "id", fmt.Sprintf("%d", vlan.ID))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create VLAN interface: %w", err)
	}

	// Set IP address
	if vlan.IP != "" && vlan.Subnet != "" {
		cidr := fmt.Sprintf("%s/%s", vlan.IP, vlan.Subnet)
		cmd = exec.Command("ip", "addr", "add", cidr, "dev", ifaceName)
		if err := cmd.Run(); err != nil {
			// Cleanup on error
			exec.Command("ip", "link", "del", ifaceName).Run()
			return fmt.Errorf("failed to set IP address: %w", err)
		}
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", ifaceName, "up")
	if err := cmd.Run(); err != nil {
		exec.Command("ip", "link", "del", ifaceName).Run()
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	// Setup bridge for VLAN if needed
	if err := vm.setupVLANBridge(vlan, ifaceName); err != nil {
		exec.Command("ip", "link", "del", ifaceName).Run()
		return fmt.Errorf("failed to setup bridge: %w", err)
	}

	// Configure guest isolation if enabled
	if vlan.Isolated {
		if err := vm.setupGuestIsolation(ifaceName); err != nil {
			return fmt.Errorf("failed to setup guest isolation: %w", err)
		}
	}

	vm.vlans[vlan.ID] = vlan
	return nil
}

// setupVLANBridge creates a bridge for the VLAN
func (vm *VLANManager) setupVLANBridge(vlan *VLAN, ifaceName string) error {
	bridgeName := fmt.Sprintf("br-vlan%d", vlan.ID)

	// Create bridge
	cmd := exec.Command("ip", "link", "add", bridgeName, "type", "bridge")
	if err := cmd.Run(); err != nil {
		// Bridge might already exist
		if err.Error() != "exit status 2" {
			return err
		}
	}

	// Add VLAN interface to bridge
	cmd = exec.Command("ip", "link", "set", ifaceName, "master", bridgeName)
	if err := cmd.Run(); err != nil {
		return err
	}

	// Bring bridge up
	cmd = exec.Command("ip", "link", "set", bridgeName, "up")
	return cmd.Run()
}

// setupGuestIsolation configures isolation for guest networks
func (vm *VLANManager) setupGuestIsolation(ifaceName string) error {
	// Prevent clients from communicating with each other
	// Enable client isolation using ebtables
	cmd := exec.Command("ebtables", "-A", "FORWARD",
		"-i", ifaceName, "-o", ifaceName, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return err
	}

	// Allow traffic to/from router only
	cmd = exec.Command("ebtables", "-I", "FORWARD", "1",
		"-p", "IPv4", "--ip-proto", "tcp", "-j", "ACCEPT")
	return cmd.Run()
}

// DeleteVLAN removes a VLAN
func (vm *VLANManager) DeleteVLAN(vlanID int) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	vlan, exists := vm.vlans[vlanID]
	if !exists {
		return fmt.Errorf("VLAN %d not found", vlanID)
	}

	ifaceName := fmt.Sprintf("%s.%d", vlan.ParentIface, vlan.ID)
	bridgeName := fmt.Sprintf("br-vlan%d", vlan.ID)

	// Delete bridge
	exec.Command("ip", "link", "set", bridgeName, "down").Run()
	exec.Command("ip", "link", "del", bridgeName).Run()

	// Delete VLAN interface
	exec.Command("ip", "link", "set", ifaceName, "down").Run()
	cmd := exec.Command("ip", "link", "del", ifaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete VLAN interface: %w", err)
	}

	delete(vm.vlans, vlanID)
	return nil
}

// GetVLAN retrieves a VLAN configuration
func (vm *VLANManager) GetVLAN(vlanID int) (*VLAN, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	vlan, exists := vm.vlans[vlanID]
	if !exists {
		return nil, fmt.Errorf("VLAN %d not found", vlanID)
	}

	return vlan, nil
}

// ListVLANs returns all VLANs
func (vm *VLANManager) ListVLANs() []*VLAN {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	vlans := make([]*VLAN, 0, len(vm.vlans))
	for _, vlan := range vm.vlans {
		vlans = append(vlans, vlan)
	}

	return vlans
}

// SetupVLANTagging configures VLAN tagging on a switch port
func SetupVLANTagging(iface string, vlanIDs []int) error {
	// Enable 802.1Q on interface
	for _, vlanID := range vlanIDs {
		cmd := exec.Command("ip", "link", "add", "link", iface,
			"name", fmt.Sprintf("%s.%d", iface, vlanID),
			"type", "vlan", "id", fmt.Sprintf("%d", vlanID))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to setup VLAN %d: %w", vlanID, err)
		}
	}

	return nil
}
