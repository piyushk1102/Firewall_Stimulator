import ipaddress
import csv
from collections import namedtuple

# Define a Rule namedtuple for easy rule representation
Rule = namedtuple('Rule', ['action', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port'])

class FirewallSimulator:
    def __init__(self):
        self.rules = []

    def add_rule(self, action, protocol, src_ip, src_port, dst_ip, dst_port):
        """Add a new rule to the firewall."""
        rule = Rule(action, protocol, src_ip, src_port, dst_ip, dst_port)
        self.rules.append(rule)

    def load_rules_from_csv(self, filename):
        """Load rules from a CSV file."""
        with open(filename, 'r') as f:
            reader = csv.reader(f)
            next(reader)  # Skip header row
            for row in reader:
                self.add_rule(*row)

    def save_rules_to_csv(self, filename):
        """Save current rules to a CSV file."""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Action', 'Protocol', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port'])
            for rule in self.rules:
                writer.writerow(rule)

    def check_packet(self, protocol, src_ip, src_port, dst_ip, dst_port):
        """Check if a packet should be allowed or blocked based on the rules."""
        for rule in self.rules:
            if self._match_rule(rule, protocol, src_ip, src_port, dst_ip, dst_port):
                return rule.action
        return "BLOCK"  # Default action if no rules match

    def _match_rule(self, rule, protocol, src_ip, src_port, dst_ip, dst_port):
        """Check if a packet matches a specific rule."""
        if rule.protocol != '*' and rule.protocol.lower() != protocol.lower():
            return False
        
        if rule.src_ip != '*' and not self._ip_in_network(src_ip, rule.src_ip):
            return False
        
        if rule.dst_ip != '*' and not self._ip_in_network(dst_ip, rule.dst_ip):
            return False
        
        if rule.src_port != '*' and int(rule.src_port) != int(src_port):
            return False
        
        if rule.dst_port != '*' and int(rule.dst_port) != int(dst_port):
            return False
        
        return True

    def _ip_in_network(self, ip, network):
        """Check if an IP is in a given network."""
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)
        except ValueError:
            return False

    def simulate_packet(self, protocol, src_ip, src_port, dst_ip, dst_port):
        """Simulate a packet and decide whether to allow or block it."""
        action = self.check_packet(protocol, src_ip, src_port, dst_ip, dst_port)
        print(f"Packet: {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Action: {action}")
        return action

# Example usage
if __name__ == "__main__":
    firewall = FirewallSimulator()

    # Add some rules
    firewall.add_rule("ALLOW", "TCP", "192.168.1.0/24", "*", "10.0.0.0/8", "80")
    firewall.add_rule("BLOCK", "UDP", "*", "*", "*", "53")
    firewall.add_rule("ALLOW", "ICMP", "*", "*", "*", "*")

    # Save rules to CSV
    firewall.save_rules_to_csv("firewall_rules.csv")

    # Load rules from CSV
    firewall.load_rules_from_csv("firewall_rules.csv")

    # Simulate some packets
    firewall.simulate_packet("TCP", "192.168.1.100", "12345", "10.0.0.1", "80")
    firewall.simulate_packet("UDP", "8.8.8.8", "53", "192.168.1.100", "12345")
    firewall.simulate_packet("ICMP", "172.16.0.1", "*", "192.168.1.100", "*")
    firewall.simulate_packet("TCP", "172.16.0.1", "12345", "10.0.0.1", "80")