#!/usr/bin/env python3
# massJARM is a threaded implementation of JARM: An active Transport Layer Security (TLS) server fingerprinting tool located at https://github.com/salesforce/jarm
# Modified by Jerzy 'Yuri' Kramarz to include threading queue model to increase the speed of execution
# Inspired by: 
# - Original JARM implementation https://github.com/salesforce/jarm 
# - jarmscan https://github.com/hdm/jarm-go
# -----------------------------------------------

from __future__ import print_function
import os
import sys
import csv
import time
import socket
import struct
import codecs
import random
import hashlib
import argparse
import threading
import re
from queue import Queue
from datetime import datetime
from collections import defaultdict
import ipaddress

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    @staticmethod
    def disable():
        Colors.HEADER = ''
        Colors.BLUE = ''
        Colors.CYAN = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.RED = ''
        Colors.ENDC = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''

# Common SSL/TLS ports to try if none specified
DEFAULT_SSL_PORTS = [443, 8443, 8080, 8000]

class OutputFormatter:
    """Handles formatted output for results"""
    def __init__(self, format_type='csv', use_colors=True, quiet=False):
        self.format_type = format_type
        self.use_colors = use_colors
        self.quiet = quiet
        self.results_buffer = []
        self.lock = threading.Lock()
        
        if not use_colors or not sys.stdout.isatty():
            Colors.disable()
    
    def add_result(self, result):
        """Add a result to the buffer"""
        with self.lock:
            self.results_buffer.append(result)
    
    def print_header(self):
        """Print appropriate header based on format"""
        if self.format_type == 'csv':
            print("host,port,jarm")
        elif self.format_type == 'table':
            print(f"\n{Colors.BOLD}{'Host':<30} {'Port':<8} {'JARM Hash':<64} {'Status':<10}{Colors.ENDC}")
            print("-" * 115)
        elif self.format_type == 'json':
            print("[")
    
    def format_result(self, result):
        """Format a single result based on output type"""
        if self.format_type == 'csv':
            return f"{result['host']},{result['port']},{result['jarm']}"
        
        elif self.format_type == 'table':
            status = 'ACTIVE' if result['jarm'] != '0' * 62 else 'NO TLS'
            status_color = Colors.GREEN if status == 'ACTIVE' else Colors.RED
            
            return (f"{result['host']:<30} "
                   f"{result['port']:<8} "
                   f"{Colors.CYAN}{result['jarm']:<64}{Colors.ENDC} "
                   f"{status_color}{status:<10}{Colors.ENDC}")
        
        elif self.format_type == 'json':
            import json
            return json.dumps(result, indent=2) + ","
        
        elif self.format_type == 'simple':
            if result['jarm'] != '0' * 62:
                return f"{Colors.GREEN}[+]{Colors.ENDC} {result['host']}:{result['port']} - {result['jarm']}"
            else:
                return f"{Colors.RED}[-]{Colors.ENDC} {result['host']}:{result['port']} - No TLS/Timeout"
    
    def print_results(self):
        """Print all buffered results"""
        with self.lock:
            for i, result in enumerate(self.results_buffer):
                output = self.format_result(result)
                if self.format_type == 'json' and i == len(self.results_buffer) - 1:
                    output = output.rstrip(',')
                print(output)
            
            if self.format_type == 'json':
                print("]")

class ProgressTracker:
    """Handles progress tracking with clean output"""
    def __init__(self, total, enabled=True):
        self.total = total
        self.completed = 0
        self.enabled = enabled
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.last_update = 0
    
    def increment(self):
        """Increment progress counter"""
        with self.lock:
            self.completed += 1
            current_time = time.time()
            
            # Update every 0.1 seconds to avoid too frequent updates
            if self.enabled and current_time - self.last_update > 0.1:
                self.update_display()
                self.last_update = current_time
    
    def update_display(self):
        """Update progress display"""
        if not self.enabled or self.total == 0:
            return
        
        progress = (self.completed / self.total) * 100
        elapsed = time.time() - self.start_time
        rate = self.completed / elapsed if elapsed > 0 else 0
        
        # Calculate ETA
        if rate > 0:
            remaining = self.total - self.completed
            eta_seconds = remaining / rate
            eta_str = self.format_time(eta_seconds)
        else:
            eta_str = "N/A"
        
        # Build progress bar
        bar_length = 30
        filled = int(bar_length * self.completed / self.total)
        bar = '█' * filled + '░' * (bar_length - filled)
        
        # Clear line and print progress
        sys.stderr.write('\r' + ' ' * 80 + '\r')
        sys.stderr.write(
            f"{Colors.YELLOW}Progress: [{bar}] {progress:.1f}% "
            f"({self.completed}/{self.total}) "
            f"Rate: {rate:.1f}/s ETA: {eta_str}{Colors.ENDC}"
        )
        sys.stderr.flush()
    
    def format_time(self, seconds):
        """Format seconds into human readable time"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds/60)}m {int(seconds%60)}s"
        else:
            return f"{int(seconds/3600)}h {int((seconds%3600)/60)}m"
    
    def finish(self):
        """Clear progress line when done"""
        if self.enabled:
            sys.stderr.write('\r' + ' ' * 80 + '\r')
            sys.stderr.flush()

class RateLimiter:
    """Simple rate limiter for controlling request frequency"""
    def __init__(self, max_per_second):
        self.max_per_second = max_per_second
        self.min_interval = 1.0 / max_per_second if max_per_second > 0 else 0
        self.last_call = defaultdict(float)
        self.lock = threading.Lock()
    
    def wait_if_needed(self, thread_id):
        if self.min_interval == 0:
            return
        
        with self.lock:
            current_time = time.time()
            time_since_last = current_time - self.last_call[thread_id]
            
            if time_since_last < self.min_interval:
                sleep_time = self.min_interval - time_since_last
                time.sleep(sleep_time)
            
            self.last_call[thread_id] = time.time()

class JARMScanner:
    def __init__(self, timeout=20, output_formatter=None, progress_tracker=None):
        self.timeout = timeout
        self.output_formatter = output_formatter
        self.progress_tracker = progress_tracker
        
    def choose_grease(self):
        """Randomly choose a GREASE value"""
        grease_list = [
            b"\x0a\x0a", b"\x1a\x1a", b"\x2a\x2a", b"\x3a\x3a",
            b"\x4a\x4a", b"\x5a\x5a", b"\x6a\x6a", b"\x7a\x7a",
            b"\x8a\x8a", b"\x9a\x9a", b"\xaa\xaa", b"\xba\xba",
            b"\xca\xca", b"\xda\xda", b"\xea\xea", b"\xfa\xfa"
        ]
        return random.choice(grease_list)
    
    def packet_building(self, jarm_details):
        """Build TLS Client Hello packet"""
        payload = b"\x16"
        
        # Version check
        version_map = {
            "TLS_1.3": (b"\x03\x01", b"\x03\x03"),
            "SSLv3": (b"\x03\x00", b"\x03\x00"),
            "TLS_1": (b"\x03\x01", b"\x03\x01"),
            "TLS_1.1": (b"\x03\x02", b"\x03\x02"),
            "TLS_1.2": (b"\x03\x03", b"\x03\x03")
        }
        
        payload_ver, client_hello_ver = version_map.get(jarm_details[2], (b"\x03\x03", b"\x03\x03"))
        payload += payload_ver
        client_hello = client_hello_ver
        
        # Random values
        client_hello += os.urandom(32)
        session_id = os.urandom(32)
        session_id_length = struct.pack(">B", len(session_id))
        client_hello += session_id_length + session_id
        
        # Ciphers
        cipher_choice = self.get_ciphers(jarm_details)
        client_suites_length = struct.pack(">H", len(cipher_choice))
        client_hello += client_suites_length + cipher_choice
        client_hello += b"\x01\x00"  # compression methods
        
        # Extensions
        extensions = self.get_extensions(jarm_details)
        client_hello += extensions
        
        # Finish packet
        inner_length = b"\x00" + struct.pack(">H", len(client_hello))
        handshake_protocol = b"\x01" + inner_length + client_hello
        outer_length = struct.pack(">H", len(handshake_protocol))
        payload += outer_length + handshake_protocol
        
        return payload
    
    def get_ciphers(self, jarm_details):
        """Get cipher list based on configuration"""
        cipher_lists = {
            "ALL": [
                b"\x00\x16", b"\x00\x33", b"\x00\x67", b"\xc0\x9e", b"\xc0\xa2",
                b"\x00\x9e", b"\x00\x39", b"\x00\x6b", b"\xc0\x9f", b"\xc0\xa3",
                b"\x00\x9f", b"\x00\x45", b"\x00\xbe", b"\x00\x88", b"\x00\xc4",
                b"\x00\x9a", b"\xc0\x08", b"\xc0\x09", b"\xc0\x23", b"\xc0\xac",
                b"\xc0\xae", b"\xc0\x2b", b"\xc0\x0a", b"\xc0\x24", b"\xc0\xad",
                b"\xc0\xaf", b"\xc0\x2c", b"\xc0\x72", b"\xc0\x73", b"\xcc\xa9",
                b"\x13\x02", b"\x13\x01", b"\xcc\x14", b"\xc0\x07", b"\xc0\x12",
                b"\xc0\x13", b"\xc0\x27", b"\xc0\x2f", b"\xc0\x14", b"\xc0\x28",
                b"\xc0\x30", b"\xc0\x60", b"\xc0\x61", b"\xc0\x76", b"\xc0\x77",
                b"\xcc\xa8", b"\x13\x05", b"\x13\x04", b"\x13\x03", b"\xcc\x13",
                b"\xc0\x11", b"\x00\x0a", b"\x00\x2f", b"\x00\x3c", b"\xc0\x9c",
                b"\xc0\xa0", b"\x00\x9c", b"\x00\x35", b"\x00\x3d", b"\xc0\x9d",
                b"\xc0\xa1", b"\x00\x9d", b"\x00\x41", b"\x00\xba", b"\x00\x84",
                b"\x00\xc0", b"\x00\x07", b"\x00\x04", b"\x00\x05"
            ],
            "NO1.3": [
                b"\x00\x16", b"\x00\x33", b"\x00\x67", b"\xc0\x9e", b"\xc0\xa2",
                b"\x00\x9e", b"\x00\x39", b"\x00\x6b", b"\xc0\x9f", b"\xc0\xa3",
                b"\x00\x9f", b"\x00\x45", b"\x00\xbe", b"\x00\x88", b"\x00\xc4",
                b"\x00\x9a", b"\xc0\x08", b"\xc0\x09", b"\xc0\x23", b"\xc0\xac",
                b"\xc0\xae", b"\xc0\x2b", b"\xc0\x0a", b"\xc0\x24", b"\xc0\xad",
                b"\xc0\xaf", b"\xc0\x2c", b"\xc0\x72", b"\xc0\x73", b"\xcc\xa9",
                b"\xcc\x14", b"\xc0\x07", b"\xc0\x12", b"\xc0\x13", b"\xc0\x27",
                b"\xc0\x2f", b"\xc0\x14", b"\xc0\x28", b"\xc0\x30", b"\xc0\x60",
                b"\xc0\x61", b"\xc0\x76", b"\xc0\x77", b"\xcc\xa8", b"\xcc\x13",
                b"\xc0\x11", b"\x00\x0a", b"\x00\x2f", b"\x00\x3c", b"\xc0\x9c",
                b"\xc0\xa0", b"\x00\x9c", b"\x00\x35", b"\x00\x3d", b"\xc0\x9d",
                b"\xc0\xa1", b"\x00\x9d", b"\x00\x41", b"\x00\xba", b"\x00\x84",
                b"\x00\xc0", b"\x00\x07", b"\x00\x04", b"\x00\x05"
            ]
        }
        
        cipher_list = cipher_lists.get(jarm_details[3], cipher_lists["ALL"])
        
        # Reorder ciphers if needed
        if jarm_details[4] != "FORWARD":
            cipher_list = self.cipher_mung(cipher_list, jarm_details[4])
        
        # Add GREASE if applicable
        if jarm_details[5] == "GREASE":
            cipher_list.insert(0, self.choose_grease())
        
        return b''.join(cipher_list)
    
    def cipher_mung(self, ciphers, request):
        """Reorder ciphers based on request type"""
        output = []
        cipher_len = len(ciphers)
        
        if request == "REVERSE":
            output = ciphers[::-1]
        elif request == "BOTTOM_HALF":
            if cipher_len % 2 == 1:
                output = ciphers[int(cipher_len/2)+1:]
            else:
                output = ciphers[int(cipher_len/2):]
        elif request == "TOP_HALF":
            if cipher_len % 2 == 1:
                output.append(ciphers[int(cipher_len/2)])
            output += self.cipher_mung(self.cipher_mung(ciphers, "REVERSE"), "BOTTOM_HALF")
        elif request == "MIDDLE_OUT":
            middle = int(cipher_len/2)
            if cipher_len % 2 == 1:
                output.append(ciphers[middle])
                for i in range(1, middle+1):
                    output.append(ciphers[middle + i])
                    output.append(ciphers[middle - i])
            else:
                for i in range(1, middle+1):
                    output.append(ciphers[middle-1 + i])
                    output.append(ciphers[middle - i])
        
        return output
    
    def get_extensions(self, jarm_details):
        """Build TLS extensions"""
        all_extensions = b""
        grease = False
        
        # GREASE
        if jarm_details[5] == "GREASE":
            all_extensions += self.choose_grease() + b"\x00\x00"
            grease = True
        
        # Server name
        all_extensions += self.extension_server_name(jarm_details[0])
        
        # Other extensions
        all_extensions += b"\x00\x17\x00\x00"  # extended_master_secret
        all_extensions += b"\x00\x01\x00\x01\x01"  # max_fragment_length
        all_extensions += b"\xff\x01\x00\x01\x00"  # renegotiation_info
        all_extensions += b"\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"  # supported_groups
        all_extensions += b"\x00\x0b\x00\x02\x01\x00"  # ec_point_formats
        all_extensions += b"\x00\x23\x00\x00"  # session_ticket
        
        # ALPN
        all_extensions += self.app_layer_proto_negotiation(jarm_details)
        
        # Signature algorithms
        all_extensions += b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01"
        
        # Key share
        all_extensions += self.key_share(grease)
        
        # PSK key exchange modes
        all_extensions += b"\x00\x2d\x00\x02\x01\x01"
        
        # Supported versions
        if jarm_details[2] == "TLS_1.3" or jarm_details[7] == "1.2_SUPPORT":
            all_extensions += self.supported_versions(jarm_details, grease)
        
        extension_length = len(all_extensions)
        return struct.pack(">H", extension_length) + all_extensions
    
    def extension_server_name(self, host):
        """Build SNI extension"""
        ext_sni = b"\x00\x00"
        ext_sni_length = len(host) + 5
        ext_sni += struct.pack(">H", ext_sni_length)
        ext_sni_length2 = len(host) + 3
        ext_sni += struct.pack(">H", ext_sni_length2)
        ext_sni += b"\x00"
        ext_sni_length3 = len(host)
        ext_sni += struct.pack(">H", ext_sni_length3)
        ext_sni += host.encode()
        return ext_sni
    
    def app_layer_proto_negotiation(self, jarm_details):
        """Build ALPN extension"""
        ext = b"\x00\x10"
        
        if jarm_details[6] == "RARE_APLN":
            alpns = [
                b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39",
                b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30",
                b"\x06\x73\x70\x64\x79\x2f\x31",
                b"\x06\x73\x70\x64\x79\x2f\x32",
                b"\x06\x73\x70\x64\x79\x2f\x33",
                b"\x03\x68\x32\x63",
                b"\x02\x68\x71"
            ]
        else:
            alpns = [
                b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39",
                b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30",
                b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x31",
                b"\x06\x73\x70\x64\x79\x2f\x31",
                b"\x06\x73\x70\x64\x79\x2f\x32",
                b"\x06\x73\x70\x64\x79\x2f\x33",
                b"\x02\x68\x32",
                b"\x03\x68\x32\x63",
                b"\x02\x68\x71"
            ]
        
        if jarm_details[8] != "FORWARD":
            alpns = self.cipher_mung(alpns, jarm_details[8])
        
        all_alpns = b''.join(alpns)
        second_length = len(all_alpns)
        first_length = second_length + 2
        ext += struct.pack(">H", first_length)
        ext += struct.pack(">H", second_length)
        ext += all_alpns
        return ext
    
    def key_share(self, grease):
        """Build key share extension"""
        ext = b"\x00\x33"
        
        if grease:
            share_ext = self.choose_grease() + b"\x00\x01\x00"
        else:
            share_ext = b""
        
        share_ext += b"\x00\x1d"  # group
        share_ext += b"\x00\x20"  # key_exchange_length
        share_ext += os.urandom(32)
        
        second_length = len(share_ext)
        first_length = second_length + 2
        ext += struct.pack(">H", first_length)
        ext += struct.pack(">H", second_length)
        ext += share_ext
        return ext
    
    def supported_versions(self, jarm_details, grease):
        """Build supported versions extension"""
        if jarm_details[7] == "1.2_SUPPORT":
            tls = [b"\x03\x01", b"\x03\x02", b"\x03\x03"]
        else:
            tls = [b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"]
        
        if jarm_details[8] != "FORWARD":
            tls = self.cipher_mung(tls, jarm_details[8])
        
        ext = b"\x00\x2b"
        
        if grease:
            versions = self.choose_grease()
        else:
            versions = b""
        
        for version in tls:
            versions += version
        
        second_length = len(versions)
        first_length = second_length + 1
        ext += struct.pack(">H", first_length)
        ext += struct.pack(">B", second_length)
        ext += versions
        return ext
    
    def send_packet(self, packet, destination_host, destination_port):
        """Send packet and receive response"""
        try:
            # Check if input is IP or domain
            try:
                ipaddress.ip_address(destination_host)
                raw_ip = True
                ip = destination_host
            except ValueError:
                raw_ip = False
                ip = None
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((destination_host, int(destination_port)))
            
            # Get IP if domain was provided
            if not raw_ip:
                ip = sock.getpeername()[0]
            
            sock.sendall(packet)
            data = sock.recv(1484)
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            
            return bytearray(data), ip
        
        except socket.timeout:
            if 'sock' in locals():
                sock.close()
            return "TIMEOUT", ip
        except Exception as e:
            if 'sock' in locals():
                sock.close()
            return None, ip
    
    def read_packet(self, data):
        """Parse server response"""
        try:
            if data is None:
                return "|||"
            
            jarm = ""
            
            # Check for alert or error
            if data[0] == 21:
                return "|||"
            
            # Check for server hello
            elif data[0] == 22 and data[5] == 2:
                server_hello_length = int.from_bytes(data[3:5], "big")
                counter = data[43]
                
                # Extract cipher
                selected_cipher = data[counter+44:counter+46]
                jarm += codecs.encode(selected_cipher, 'hex').decode('ascii')
                jarm += "|"
                
                # Extract version
                version = data[9:11]
                jarm += codecs.encode(version, 'hex').decode('ascii')
                jarm += "|"
                
                # Extract extensions
                extensions = self.extract_extension_info(data, counter, server_hello_length)
                jarm += extensions
                
                return jarm
            else:
                return "|||"
        
        except Exception:
            return "|||"
    
    def extract_extension_info(self, data, counter, server_hello_length):
        """Extract extension information from server hello"""
        try:
            if (data[counter+47] == 11) or \
               (data[counter+50:counter+53] == b"\x0e\xac\x0b") or \
               (data[82:85] == b"\x0f\xf0\x0b") or \
               (counter+42 >= server_hello_length):
                return "|"
            
            count = 49 + counter
            length = int(codecs.encode(data[counter+47:counter+49], 'hex'), 16)
            maximum = length + (count - 1)
            types = []
            values = []
            
            # Collect extension types and values
            while count < maximum:
                types.append(data[count:count+2])
                ext_length = int(codecs.encode(data[count+2:count+4], 'hex'), 16)
                if ext_length == 0:
                    count += 4
                    values.append("")
                else:
                    values.append(data[count+4:count+4+ext_length])
                    count += ext_length + 4
            
            result = ""
            
            # Find ALPN
            alpn = self.find_extension(b"\x00\x10", types, values)
            result += str(alpn) + "|"
            
            # Add extension types
            for i, ext_type in enumerate(types):
                result += codecs.encode(ext_type, 'hex').decode('ascii')
                if i < len(types) - 1:
                    result += "-"
            
            return result
        
        except Exception:
            return "|"
    
    def find_extension(self, ext_type, types, values):
        """Find specific extension in list"""
        for i, t in enumerate(types):
            if t == ext_type:
                if ext_type == b"\x00\x10":  # ALPN
                    return values[i][3:].decode()
                else:
                    return values[i].hex()
        return ""
    
    def jarm_hash(self, jarm_raw):
        """Calculate JARM hash from raw fingerprint"""
        if jarm_raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||":
            return "0" * 62
        
        fuzzy_hash = ""
        handshakes = jarm_raw.split(",")
        alpns_and_ext = ""
        
        for handshake in handshakes:
            components = handshake.split("|")
            fuzzy_hash += self.cipher_bytes(components[0])
            fuzzy_hash += self.version_byte(components[1])
            alpns_and_ext += components[2]
            alpns_and_ext += components[3]
        
        sha256 = hashlib.sha256(alpns_and_ext.encode()).hexdigest()
        fuzzy_hash += sha256[0:32]
        
        return fuzzy_hash
    
    def cipher_bytes(self, cipher):
        """Convert cipher to fuzzy hash bytes"""
        if cipher == "":
            return "00"
        
        cipher_list = [
            b"\x00\x04", b"\x00\x05", b"\x00\x07", b"\x00\x0a", b"\x00\x16",
            b"\x00\x2f", b"\x00\x33", b"\x00\x35", b"\x00\x39", b"\x00\x3c",
            b"\x00\x3d", b"\x00\x41", b"\x00\x45", b"\x00\x67", b"\x00\x6b",
            b"\x00\x84", b"\x00\x88", b"\x00\x9a", b"\x00\x9c", b"\x00\x9d",
            b"\x00\x9e", b"\x00\x9f", b"\x00\xba", b"\x00\xbe", b"\x00\xc0",
            b"\x00\xc4", b"\xc0\x07", b"\xc0\x08", b"\xc0\x09", b"\xc0\x0a",
            b"\xc0\x11", b"\xc0\x12", b"\xc0\x13", b"\xc0\x14", b"\xc0\x23",
            b"\xc0\x24", b"\xc0\x27", b"\xc0\x28", b"\xc0\x2b", b"\xc0\x2c",
            b"\xc0\x2f", b"\xc0\x30", b"\xc0\x60", b"\xc0\x61", b"\xc0\x72",
            b"\xc0\x73", b"\xc0\x76", b"\xc0\x77", b"\xc0\x9c", b"\xc0\x9d",
            b"\xc0\x9e", b"\xc0\x9f", b"\xc0\xa0", b"\xc0\xa1", b"\xc0\xa2",
            b"\xc0\xa3", b"\xc0\xac", b"\xc0\xad", b"\xc0\xae", b"\xc0\xaf",
            b'\xcc\x13', b'\xcc\x14', b'\xcc\xa8', b'\xcc\xa9', b'\x13\x01',
            b'\x13\x02', b'\x13\x03', b'\x13\x04', b'\x13\x05'
        ]
        
        for count, bytes_val in enumerate(cipher_list, 1):
            if cipher == codecs.encode(bytes_val, 'hex').decode('ascii'):
                hex_value = hex(count)[2:]
                return hex_value.zfill(2)
        
        return "00"
    
    def version_byte(self, version):
        """Convert version to single byte"""
        if version == "":
            return "0"
        
        options = "abcdef"
        try:
            count = int(version[3:4])
            return options[count]
        except:
            return "0"
    
    def scan_target(self, host, port):
        """Scan a single host:port combination"""
        # Define all JARM probes
        probes = [
            [host, port, "TLS_1.2", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.2_SUPPORT", "REVERSE"],
            [host, port, "TLS_1.2", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.2_SUPPORT", "FORWARD"],
            [host, port, "TLS_1.2", "ALL", "TOP_HALF", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"],
            [host, port, "TLS_1.2", "ALL", "BOTTOM_HALF", "NO_GREASE", "RARE_APLN", "NO_SUPPORT", "FORWARD"],
            [host, port, "TLS_1.2", "ALL", "MIDDLE_OUT", "GREASE", "RARE_APLN", "NO_SUPPORT", "REVERSE"],
            [host, port, "TLS_1.1", "ALL", "FORWARD", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"],
            [host, port, "TLS_1.3", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "REVERSE"],
            [host, port, "TLS_1.3", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"],
            [host, port, "TLS_1.3", "NO1.3", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"],
            [host, port, "TLS_1.3", "ALL", "MIDDLE_OUT", "GREASE", "APLN", "1.3_SUPPORT", "REVERSE"]
        ]
        
        jarm_raw = ""
        ip = None
        
        # Send all probes
        for i, probe in enumerate(probes):
            payload = self.packet_building(probe)
            server_hello, probe_ip = self.send_packet(payload, host, port)
            
            if probe_ip:
                ip = probe_ip
            
            if server_hello == "TIMEOUT":
                jarm_raw = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||"
                break
            
            ans = self.read_packet(server_hello)
            jarm_raw += ans
            
            if i < len(probes) - 1:
                jarm_raw += ","
        
        # Calculate JARM hash
        jarm_hash = self.jarm_hash(jarm_raw)
        
        return {
            'host': host,
            'ip': ip or host,
            'port': port,
            'jarm': jarm_hash,
            'timestamp': datetime.now().isoformat()
        }

class WorkerThread(threading.Thread):
    """Worker thread for processing targets"""
    def __init__(self, queue, scanner, rate_limiter, thread_id, output_formatter, progress_tracker):
        super().__init__()
        self.queue = queue
        self.scanner = scanner
        self.rate_limiter = rate_limiter
        self.thread_id = thread_id
        self.output_formatter = output_formatter
        self.progress_tracker = progress_tracker
        self.daemon = True
    
    def run(self):
        while True:
            target = self.queue.get()
            if target is None:
                break
            
            # Apply rate limiting
            self.rate_limiter.wait_if_needed(self.thread_id)
            
            host, port = target
            try:
                result = self.scanner.scan_target(host, port)
                self.output_formatter.add_result(result)
            except Exception as e:
                print(f"Error scanning {host}:{port} - {str(e)}", file=sys.stderr)
            
            self.progress_tracker.increment()
            self.queue.task_done()

def parse_target(target):
    """Parse target string to extract host and port(s)"""
    target = target.strip()
    if not target:
        return None, []
    
    # Check if port is specified
    if ':' in target and not target.count(':') > 1:  # Avoid IPv6 confusion
        parts = target.rsplit(':', 1)
        try:
            port = int(parts[1])
            return parts[0], [port]
        except ValueError:
            pass
    
    # No port specified, return host with default ports
    return target, None

def is_valid_host(host):
    """Check if host is valid IP or domain"""
    # Check if it's an IP
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    
    # Basic domain validation
    if '.' in host and len(host) > 3:
        return True
    
    return False

def main():
    parser = argparse.ArgumentParser(
        description='massJARM - TLS fingerprinting tool by op7ic',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  %(prog)s -t example.com
  %(prog)s -t example.com:8443 --format table
  %(prog)s -i targets.txt -o results.csv --format csv
  %(prog)s -i targets.txt --threads 10 --rate 50 --format simple
  %(prog)s -i targets.txt --format json --no-progress
        '''
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-t', '--target', help='Single target (domain or IP, with optional port)')
    input_group.add_argument('-i', '--input', help='Input file with targets (one per line)')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument('--format', choices=['csv', 'table', 'json', 'simple'], 
                       default='csv', help='Output format (default: csv)')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--no-progress', action='store_true', help='Disable progress bar')
    
    # Scan options
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--rate', type=int, default=0, help='Max requests per second per thread (0=unlimited)')
    parser.add_argument('--timeout', type=int, default=2, help='Socket timeout in seconds (default: 2)')
    parser.add_argument('--ports', nargs='+', type=int, help='Custom ports to try if none specified')
    
    args = parser.parse_args()
    
    # Determine ports to use
    default_ports = args.ports if args.ports else DEFAULT_SSL_PORTS
    
    # Collect targets
    targets = []
    
    if args.target:
        # Single target
        host, ports = parse_target(args.target)
        if host and is_valid_host(host):
            if ports:
                for port in ports:
                    targets.append((host, port))
            else:
                for port in default_ports:
                    targets.append((host, port))
    else:
        # File input
        try:
            with open(args.input, 'r') as f:
                for line in f:
                    host, ports = parse_target(line)
                    if host and is_valid_host(host):
                        if ports:
                            for port in ports:
                                targets.append((host, port))
                        else:
                            for port in default_ports:
                                targets.append((host, port))
        except FileNotFoundError:
            print(f"Error: Input file '{args.input}' not found", file=sys.stderr)
            sys.exit(1)
    
    if not targets:
        print("Error: No valid targets found", file=sys.stderr)
        sys.exit(1)
    
    # Initialize components
    output_formatter = OutputFormatter(
        format_type=args.format,
        use_colors=not args.no_color,
        quiet=args.no_progress
    )
    progress_tracker = ProgressTracker(
        total=len(targets),
        enabled=not args.no_progress
    )
    scanner = JARMScanner(
        timeout=args.timeout,
        output_formatter=output_formatter,
        progress_tracker=progress_tracker
    )
    rate_limiter = RateLimiter(args.rate)
    
    # Print header
    if args.output:
        # Redirect stdout to file
        original_stdout = sys.stdout
        sys.stdout = open(args.output, 'w')
    
    output_formatter.print_header()
    
    # Print scan info to stderr
    print(f"\n{Colors.BOLD}Starting JARM scan{Colors.ENDC}", file=sys.stderr)
    print(f"Targets: {len(targets)} | Threads: {args.threads} | Timeout: {args.timeout}s\n", file=sys.stderr)
    
    # Create work queue
    queue = Queue()
    
    # Start worker threads
    threads = []
    for i in range(args.threads):
        thread = WorkerThread(queue, scanner, rate_limiter, i, output_formatter, progress_tracker)
        thread.start()
        threads.append(thread)
    
    # Add targets to queue
    for target in targets:
        queue.put(target)
    
    # Wait for completion
    queue.join()
    
    # Stop threads
    for _ in threads:
        queue.put(None)
    
    for thread in threads:
        thread.join()
    
    # Clear progress and print results
    progress_tracker.finish()
    output_formatter.print_results()
    
    # Print summary
    print(f"\n{Colors.GREEN}Scan complete!{Colors.ENDC}", file=sys.stderr)
    print(f"Total targets scanned: {progress_tracker.completed}", file=sys.stderr)
    
    # Count active TLS services
    active_count = sum(1 for r in output_formatter.results_buffer if r['jarm'] != '0' * 62)
    print(f"Active TLS services: {active_count}/{progress_tracker.completed}", file=sys.stderr)
    
    # Restore stdout if redirected
    if args.output:
        sys.stdout.close()
        sys.stdout = original_stdout
        print(f"Results saved to: {args.output}", file=sys.stderr)

if __name__ == '__main__':
    main()