use anyhow::{Result, anyhow};
use std::sync::{Arc, RwLock};
use ipnetwork::IpNetwork;

/// Global configuration for the framework
#[derive(Clone, Debug)]
pub struct GlobalConfig {
    /// Global target - can be a single IP or CIDR subnet
    target: Arc<RwLock<Option<TargetConfig>>>,
}

#[derive(Clone, Debug)]
pub enum TargetConfig {
    /// Single IP address or hostname
    Single(String),
    /// CIDR subnet (e.g., "192.168.1.0/24")
    Subnet(IpNetwork),
}

impl GlobalConfig {
    /// Create a new global configuration
    pub fn new() -> Self {
        Self {
            target: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the global target (IP, hostname, or CIDR subnet)
    pub fn set_target(&self, target: &str) -> Result<()> {
        let trimmed = target.trim();
        
        if trimmed.is_empty() {
            return Err(anyhow!("Target cannot be empty"));
        }

        // Try to parse as CIDR subnet first
        if let Ok(network) = trimmed.parse::<IpNetwork>() {
            let mut target_guard = self.target.write().unwrap();
            *target_guard = Some(TargetConfig::Subnet(network));
            return Ok(());
        }

        // Otherwise, treat as single IP or hostname
        let mut target_guard = self.target.write().unwrap();
        *target_guard = Some(TargetConfig::Single(trimmed.to_string()));
        Ok(())
    }

    /// Get the global target as a single string (for display)
    pub fn get_target(&self) -> Option<String> {
        let target_guard = self.target.read().unwrap();
        target_guard.as_ref().map(|t| match t {
            TargetConfig::Single(ip) => ip.clone(),
            TargetConfig::Subnet(net) => net.to_string(),
        })
    }

    /// Get a single IP address from the global target
    /// For subnets, returns the network address (first IP)
    pub fn get_single_target_ip(&self) -> Result<String> {
        let target_guard = self.target.read().unwrap();
        
        match target_guard.as_ref() {
            Some(TargetConfig::Single(ip)) => {
                Ok(ip.clone())
            }
            Some(TargetConfig::Subnet(net)) => {
                // Return the network address (first IP in the subnet)
                Ok(net.network().to_string())
            }
            None => Err(anyhow!("No global target set")),
        }
    }

    /// Get all IP addresses from the global target
    /// Returns a vector of IP addresses (expands subnets)
    /// For very large subnets (> 65536 IPs), returns an error
    pub fn get_target_ips(&self) -> Result<Vec<String>> {
        let target_guard = self.target.read().unwrap();
        
        match target_guard.as_ref() {
            Some(TargetConfig::Single(ip)) => {
                // For single IP/hostname, return as-is
                Ok(vec![ip.clone()])
            }
            Some(TargetConfig::Subnet(net)) => {
                // Check subnet size to prevent memory issues
                // Calculate size from prefix length: 2^(32-prefix) for IPv4, 2^(128-prefix) for IPv6
                let size = match net {
                    IpNetwork::V4(net4) => {
                        let prefix = net4.prefix() as u32;
                        if prefix >= 32 {
                            1u64
                        } else {
                            2u64.pow(32 - prefix)
                        }
                    }
                    IpNetwork::V6(net6) => {
                        let prefix = net6.prefix() as u32;
                        if prefix >= 128 {
                            1u64
                        } else {
                            // For very large IPv6 subnets, cap at u64::MAX
                            let exp = 128u32.saturating_sub(prefix);
                            if exp > 63 {
                                u64::MAX
                            } else {
                                2u64.pow(exp)
                            }
                        }
                    }
                };
                const MAX_SUBNET_SIZE: u64 = 65536; // Limit to /16 or smaller
                
                if size > MAX_SUBNET_SIZE {
                    return Err(anyhow!(
                        "Subnet too large ({} IPs). Maximum allowed: {} IPs. Use a smaller subnet or use 'get_single_target_ip' for a single IP.",
                        size, MAX_SUBNET_SIZE
                    ));
                }
                
                // Expand subnet to individual IPs
                let mut ips = Vec::new();
                for ip in net.iter() {
                    ips.push(ip.to_string());
                }
                Ok(ips)
            }
            None => Err(anyhow!("No global target set")),
        }
    }

    /// Check if global target is set
    pub fn has_target(&self) -> bool {
        let target_guard = self.target.read().unwrap();
        target_guard.is_some()
    }

    /// Check if global target is a subnet
    pub fn is_subnet(&self) -> bool {
        let target_guard = self.target.read().unwrap();
        matches!(target_guard.as_ref(), Some(TargetConfig::Subnet(_)))
    }

    /// Get the size of the target (number of IPs)
    /// For single IPs, returns 1
    /// For subnets, returns the subnet size without expanding
    pub fn get_target_size(&self) -> Option<u64> {
        let target_guard = self.target.read().unwrap();
        match target_guard.as_ref() {
            Some(TargetConfig::Single(_)) => Some(1),
            Some(TargetConfig::Subnet(net)) => {
                // Calculate size from prefix length
                let size = match net {
                    IpNetwork::V4(net4) => {
                        let prefix = net4.prefix() as u32;
                        if prefix >= 32 {
                            1u64
                        } else {
                            2u64.pow(32 - prefix)
                        }
                    }
                    IpNetwork::V6(net6) => {
                        let prefix = net6.prefix() as u32;
                        if prefix >= 128 {
                            1u64
                        } else {
                            let exp = 128u32.saturating_sub(prefix);
                            if exp > 63 {
                                u64::MAX
                            } else {
                                2u64.pow(exp)
                            }
                        }
                    }
                };
                Some(size)
            }
            None => None,
        }
    }

    /// Clear the global target
    pub fn clear_target(&self) {
        let mut target_guard = self.target.write().unwrap();
        *target_guard = None;
    }
}

/// Global configuration instance
use once_cell::sync::Lazy;

pub static GLOBAL_CONFIG: Lazy<GlobalConfig> = Lazy::new(|| GlobalConfig::new());

