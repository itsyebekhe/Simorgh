import asyncio
import base64
import json
import os
import sys
import time
import urllib.request
import urllib.parse
import socket
import ipaddress
from datetime import datetime
from typing import List, Dict, Optional, Any

# --- Imports for GeoIP ---
import requests
import geoip2.database

# ============================================================================
# CONSTANTS
# ============================================================================

GITHUB_SUB_URL = 'https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/base64/mix'
OUTPUT_DIR = 'subscriptions'
PORT_CHECK_TIMEOUT = 1.5
PARALLEL_BATCH_SIZE = 200
TOP_N_PROXIES = 15
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

# GeoIP Configuration
GEOIP_DB_PATH = 'Country.mmdb'
GEOIP_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

# Cloudflare Configuration
CF_RANGES_URL = "https://raw.githubusercontent.com/ircfspace/cf-ip-ranges/refs/heads/main/export.ipv4"

# Global Variables
GEOIP_READER = None
CF_NETWORKS = []

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def safe_base64_decode(s: str) -> bytes:
    s = s.strip()
    try:
        return base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4))
    except (TypeError, base64.binascii.Error):
        return b""

def safe_base64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('utf-8')

# --- Cloudflare Logic ---

def load_cloudflare_ranges():
    global CF_NETWORKS
    print("  - Loading Cloudflare IP ranges...")
    default_ranges = [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32",
        "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
        "2a06:98c0::/29", "2c0f:f248::/32"
    ]
    try:
        response = requests.get(CF_RANGES_URL, timeout=10)
        if response.status_code == 200:
            lines = response.text.splitlines()
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    try: CF_NETWORKS.append(ipaddress.ip_network(line))
                    except ValueError: pass
        else:
            for r in default_ranges:
                try: CF_NETWORKS.append(ipaddress.ip_network(r))
                except: pass
    except Exception:
        for r in default_ranges:
            try: CF_NETWORKS.append(ipaddress.ip_network(r))
            except: pass

def is_cloudflare(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in CF_NETWORKS:
            if ip_obj in net: return True
    except ValueError: pass
    return False

# --- GeoIP Logic ---

def download_geoip_db():
    global GEOIP_READER
    if os.path.exists(GEOIP_DB_PATH):
        file_age = time.time() - os.path.getmtime(GEOIP_DB_PATH)
        if file_age < 86400:
            print(f"  - GeoIP Database found (Age: {int(file_age/3600)}h). Loading...")
            try:
                GEOIP_READER = geoip2.database.Reader(GEOIP_DB_PATH)
                return
            except Exception: pass 

    print("  - Downloading GeoIP Database...")
    try:
        response = requests.get(GEOIP_DB_URL, stream=True, timeout=20)
        if response.status_code == 200:
            with open(GEOIP_DB_PATH, 'wb') as f:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk: f.write(chunk)
            print("  - GeoIP Database downloaded successfully.")
            GEOIP_READER = geoip2.database.Reader(GEOIP_DB_PATH)
    except Exception as e:
        print(f"  - [ERROR] GeoIP download failed: {e}")

def resolve_ip(host: str) -> Optional[str]:
    try:
        socket.inet_aton(host)
        return host
    except socket.error: pass
    try:
        return socket.gethostbyname(host)
    except Exception: return None

def get_country_code(hostname: str) -> str:
    if not hostname: return "UNK"
    ip = resolve_ip(hostname)
    if not ip: return "UNK"
    if is_cloudflare(ip): return "CF"
    if GEOIP_READER:
        try:
            response = GEOIP_READER.country(ip)
            return response.country.iso_code if response.country.iso_code else "UNK"
        except Exception: pass
    return "UNK"

# --- Parsing Logic ---

def detect_type(input_str: str) -> Optional[str]:
    input_str = input_str.strip()
    if input_str.startswith('vmess://'): return 'vmess'
    if input_str.startswith('vless://'): return 'vless'
    if input_str.startswith('trojan://'): return 'trojan'
    if input_str.startswith('ss://'): return 'ss'
    if input_str.startswith('tuic://'): return 'tuic'
    if input_str.startswith('hy2://') or input_str.startswith('hysteria2://'): return 'hy2'
    if input_str.startswith('hysteria://'): return 'hysteria'
    return None

def config_parse(input_str: str) -> Optional[Dict[str, Any]]:
    config_type = detect_type(input_str)
    if config_type == 'vmess':
        try: return json.loads(safe_base64_decode(input_str[8:]))
        except Exception: return None
    elif config_type in ['vless', 'trojan', 'tuic', 'hy2', 'ss']:
        try:
            parsed = urllib.parse.urlparse(input_str)
            params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
            if config_type == 'ss':
                user_info = urllib.parse.unquote(parsed.netloc.split('@')[0])
                decoded_user_info = user_info
                try:
                    b64_check = safe_base64_decode(user_info)
                    if b64_check and b':' in b64_check:
                        decoded_user_info = b64_check.decode('utf-8', 'ignore')
                except Exception: pass
                if ':' not in decoded_user_info: return None
                method, password = decoded_user_info.split(':', 1)
                return { 'hostname': parsed.hostname, 'port': parsed.port, 'method': method, 'password': password, 'hash': parsed.fragment }
            return {
                'protocol': config_type, 'username': parsed.username, 'hostname': parsed.hostname,
                'port': parsed.port, 'params': params, 'hash': parsed.fragment
            }
        except Exception: return None
    return None

def print_progress(current: int, total: int, message: str = ''):
    if total == 0: return
    percentage = (current / total) * 100
    bar = '=' * int(50 * current / total) + ' ' * (50 - int(50 * current / total))
    sys.stdout.write(f"\r{message} [{bar}] {percentage:.1f}% ({current}/{total})")
    sys.stdout.flush()

# --- Config Wrapper & Renaming ---

class ConfigWrapper:
    def __init__(self, config_string: str):
        self.config_string = config_string
        self.type = detect_type(config_string) or 'unknown'
        self.decoded = config_parse(config_string)

    def is_valid(self) -> bool: return self.decoded is not None
    def get_server(self) -> str:
        if not self.decoded: return ''
        return self.decoded.get('add') or self.decoded.get('hostname') or ''
    def get_port(self) -> int:
        if not self.decoded: return 0
        try: return int(self.decoded.get('port', 0))
        except (ValueError, TypeError): return 0
    def get_param(self, key: str, default: Any = None) -> Any:
        if not self.decoded: return default
        return self.decoded.get('params', {}).get(key, default)

def generate_base_name(wrapper: ConfigWrapper, latency: int) -> str:
    if not wrapper.is_valid(): return "InvalidConfig"
    protocol = wrapper.type.upper()
    country = get_country_code(wrapper.get_server())
    latency_str = f"{latency}ms"
    details = []
    if wrapper.type in ['vless', 'vmess', 'trojan']:
        security = wrapper.get_param('security', wrapper.decoded.get('tls'))
        if security in ['tls', 'reality']: details.append(security.upper())
        transport = wrapper.get_param('type', wrapper.decoded.get('net'))
        if transport and transport != 'tcp': details.append(transport.upper())
    name_parts = [protocol, country] + details + [latency_str]
    return '_'.join(filter(None, name_parts))

def rename_config(config_string: str, new_name: str) -> str:
    config_type = detect_type(config_string)
    encoded_new_name = urllib.parse.quote(new_name)
    if config_type == 'vmess':
        try:
            decoded_obj = config_parse(config_string)
            if decoded_obj:
                decoded_obj['ps'] = new_name 
                json_str = json.dumps(decoded_obj, separators=(',', ':'))
                return f"vmess://{safe_base64_encode(json_str.encode('utf-8'))}"
        except Exception: return config_string 
    elif config_type in ['vless', 'trojan', 'ss', 'tuic', 'hy2']:
        try:
            parts = list(urllib.parse.urlparse(config_string))
            parts[5] = encoded_new_name 
            return urllib.parse.urlunparse(parts)
        except Exception: return config_string
    return config_string

# --- Async Checker ---

async def check_connectivity(host: str, port: int, timeout: int) -> int:
    start_time = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        latency = (time.perf_counter() - start_time) * 1000
        writer.close()
        await writer.wait_closed()
        return int(latency)
    except Exception: return -1

async def worker(queue: asyncio.Queue, results: list, progress: dict, total: int):
    while True:
        item = await queue.get()
        if item is None: break
        host, port, config_str = item
        latency = await check_connectivity(host, port, PORT_CHECK_TIMEOUT)
        if latency != -1:
            results.append({'config': config_str, 'latency': latency})
        progress['current'] += 1
        print_progress(progress['current'], total, "Checking ports: ")
        queue.task_done()

async def check_ports_parallel(proxies_to_check: List[Dict]) -> List[Dict]:
    total_to_check = len(proxies_to_check)
    if total_to_check == 0: return []
    queue = asyncio.Queue()
    for item in proxies_to_check:
        queue.put_nowait((item['host'], item['port'], item['config']))
    live_configs, progress_tracker = [], {'current': 0}
    workers = [asyncio.create_task(worker(queue, live_configs, progress_tracker, total_to_check)) for _ in range(min(PARALLEL_BATCH_SIZE, total_to_check))]
    await queue.join()
    for _ in workers: queue.put_nowait(None)
    await asyncio.gather(*workers)
    sys.stdout.write("\n")
    return live_configs

# ============================================================================
# MAIN
# ============================================================================

def main():
    print("Starting proxy fetch and check process...")
    
    download_geoip_db()
    load_cloudflare_ranges()

    print("  - Fetching subscription file from GitHub...")
    try:
        req = urllib.request.Request(GITHUB_SUB_URL, headers={'User-Agent': USER_AGENT})
        with urllib.request.urlopen(req) as response: base64_content = response.read()
    except Exception as e:
        print(f"[ERROR] Failed to download: {e}"); sys.exit(1)

    try:
        decoded_str = safe_base64_decode(base64_content.decode('utf-8')).decode('utf-8', 'ignore')
    except Exception as e:
        print(f"[ERROR] Failed to decode: {e}"); sys.exit(1)

    all_configs = [line.strip() for line in decoded_str.splitlines() if line.strip()]
    if not all_configs: print("[WARNING] No proxy configurations found."); sys.exit(0)
    print(f"  - Found {len(all_configs)} configs.")

    unique_configs_to_check, seen_host_ports = [], set()
    print("  - Deduplicating...")
    for config in all_configs:
        wrapper = ConfigWrapper(config)
        if wrapper.is_valid():
            server, port = wrapper.get_server(), wrapper.get_port()
            if server and port > 0:
                endpoint_key = f"{server}:{port}"
                if endpoint_key not in seen_host_ports:
                    seen_host_ports.add(endpoint_key)
                    unique_configs_to_check.append({'host': server, 'port': port, 'config': config})
    
    print(f"  - Checking {len(unique_configs_to_check)} unique configs...")
    live_configs_with_latency = asyncio.run(check_ports_parallel(unique_configs_to_check))
    print(f"\n  - Found {len(live_configs_with_latency)} live proxies.")

    print("  - Renaming configurations (Unique Names)...")
    renamed_live_configs = []
    
    # Dictionary to track duplicate names
    name_counter = {}
    
    count, total_live = 0, len(live_configs_with_latency)
    
    for item in live_configs_with_latency:
        wrapper = ConfigWrapper(item['config'])
        if wrapper.is_valid():
            # 1. Generate Base Name (e.g., VLESS_US_TLS_150ms)
            base_name = generate_base_name(wrapper, item['latency'])
            
            # 2. Check for Duplicates & Append Counter
            if base_name in name_counter:
                name_counter[base_name] += 1
                final_name = f"{base_name}_{name_counter[base_name]}"
            else:
                name_counter[base_name] = 1
                final_name = base_name
            
            # 3. Rename
            renamed_config_str = rename_config(item['config'], final_name)
            renamed_live_configs.append({'config': renamed_config_str, 'latency': item['latency']})
        
        count += 1
        print_progress(count, total_live, "Renaming: ")
    print("")

    # --- Sorting & Saving ---
    categorized_configs = {}
    for item in renamed_live_configs:
        c_type = detect_type(item['config'])
        if c_type: categorized_configs.setdefault(c_type, []).append(item)
    sorted_categories = sorted(categorized_configs.keys())

    dir_normal = f"{OUTPUT_DIR}/normal"
    dir_base64 = f"{OUTPUT_DIR}/base64"
    os.makedirs(dir_normal, exist_ok=True)
    os.makedirs(dir_base64, exist_ok=True)

    top_fastest_proxies, summary_data_by_type = [], {}
    print("  - Saving subscriptions...")

    for c_type in sorted_categories:
        proxies = sorted(categorized_configs[c_type], key=lambda x: x['latency'])
        top_fastest_proxies.extend(proxies[:TOP_N_PROXIES])
        summary_data_by_type[c_type] = len(proxies)
        
        config_list = [p['config'] for p in proxies]
        normal_content = "\n".join(config_list)
        base64_content = safe_base64_encode(normal_content.encode('utf-8'))
        
        with open(f"{dir_normal}/{c_type}", "w", encoding='utf-8') as f: f.write(normal_content)
        with open(f"{dir_base64}/{c_type}", "w", encoding='utf-8') as f: f.write(base64_content)
        print(f"    - Saved {c_type}")

    # Mixed
    all_live_list = [p['config'] for p in sorted(renamed_live_configs, key=lambda x: x['latency'])]
    all_live_txt = "\n".join(all_live_list)
    all_live_b64 = safe_base64_encode(all_live_txt.encode('utf-8'))
    with open(f"{dir_normal}/mixed", "w", encoding='utf-8') as f: f.write(all_live_txt)
    with open(f"{dir_base64}/mixed", "w", encoding='utf-8') as f: f.write(all_live_b64)
    print(f"    - Saved mixed (Total: {len(all_live_list)})")

    # High Speed
    top_list = [p['config'] for p in sorted(top_fastest_proxies, key=lambda x: x['latency'])]
    top_txt = "\n".join(top_list)
    top_b64 = safe_base64_encode(top_txt.encode('utf-8'))
    with open(f"{dir_normal}/high_speed", "w", encoding='utf-8') as f: f.write(top_txt)
    with open(f"{dir_base64}/high_speed", "w", encoding='utf-8') as f: f.write(top_b64)
    print(f"    - Saved high_speed (Total: {len(top_list)})")

    # Summary
    summary = {'generated_at': datetime.now().isoformat(), 'total_scanned': len(all_configs),
               'total_live': len(renamed_live_configs), 'breakdown': summary_data_by_type}
    with open(f"{OUTPUT_DIR}/summary.json", "w", encoding='utf-8') as f: json.dump(summary, f, indent=4)
    
    print("\nProcess finished successfully!")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    main()