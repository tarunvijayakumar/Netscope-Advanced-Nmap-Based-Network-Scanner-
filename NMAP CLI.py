import nmap
import platform
import os
import pandas as pd
import re
import argparse
import ipaddress

def get_local_os():
    return platform.system()

def detect_os_bulk(subnet, save_path, custom_args, show_os_sections):
    nm = nmap.PortScanner()
    windows_hosts = []
    other_hosts = []
    raw_outputs = ""
    total_up = 0

    # Step 1: Ping scan to find live hosts
    print(f"[🔍] Performing ping scan on {subnet} ...")
    try:
        nm.scan(hosts=subnet, arguments='-sn')
    except Exception as e:
        print(f"❌ Error during ping scan: {e}")
        return

    live_hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up']
    print(f"[✅] {len(live_hosts)} live hosts found in {subnet}")

    if not live_hosts:
        print(f"[⚠️] No hosts up in subnet {subnet}")
        return

    try:
        for ip in live_hosts:
            print(f"[📡] Scanning {ip}")
            nm.scan(hosts=ip, arguments=custom_args)

            total_up += 1
            os_matches = nm[ip].get('osmatch', [])

            # Only check OS matches if -O is present
            if show_os_sections and os_matches:
                best_match = os_matches[0]
                os_name = best_match['name']
                accuracy = best_match['accuracy']
                if "windows" in os_name.lower():
                    windows_hosts.append((ip, os_name, accuracy))
                else:
                    other_hosts.append((ip, os_name, accuracy))
            elif show_os_sections:
                other_hosts.append((ip, "Unknown", 0))

            raw_outputs += f"\n[+] Scan Summary for {ip}:\n"
            for proto in nm[ip].all_protocols():
                for port in sorted(nm[ip][proto]):
                    state = nm[ip][proto][port]['state']
                    name = nm[ip][proto][port]['name']
                    raw_outputs += f"  {proto.upper()} Port {port}: {state} ({name})\n"

                    # Include per-port script output
                    script_output = nm[ip][proto][port].get('script', {})
                    for script_name, script_result in script_output.items():
                        raw_outputs += f"    - Script [{script_name}]: {script_result}\n"

            # Include hostscript output (e.g., vuln checks)
            if 'hostscript' in nm[ip]:
                raw_outputs += "\n[!] Host Script Results:\n"
                for script in nm[ip]['hostscript']:
                    raw_outputs += f"  > {script['id']}: {script['output']}\n"

            # Include OS matches only if -O
            if show_os_sections and os_matches:
                raw_outputs += "\nOS Matches:\n"
                for match in os_matches:
                    raw_outputs += f"  → {match['name']} (Accuracy: {match['accuracy']}%)\n"
                    for cls in match.get('osclass', []):
                        vendor = cls.get('vendor', 'Unknown')
                        osfamily = cls.get('osfamily', '')
                        osgen = cls.get('osgen', '')
                        ostype = cls.get('type', '')
                        raw_outputs += f"     - Class: {vendor} {osfamily} {osgen} ({ostype})\n"
                        cpes = cls.get('cpe', [])
                        if cpes:
                            raw_outputs += f"       CPEs: {', '.join(cpes)}\n"

            raw_outputs += "\n" + ("=" * 60) + "\n"

    except Exception as e:
        raw_outputs += f"❌ Error during scan: {e}\n"

    os.makedirs(save_path, exist_ok=True)
    safe_subnet = re.sub(r'[^\w.-]', '_', subnet.strip())
    safe_args = re.sub(r'[^\w.-]', '_', custom_args.strip()) if custom_args.strip() else 'default'
    filename = os.path.join(save_path, f"{safe_subnet}_{safe_args}.txt")

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"Local System OS: {get_local_os()}\n\n")

        if show_os_sections:
            f.write("--- WINDOWS HOSTS DETECTED ---\n")
            for ip, osname, acc in windows_hosts:
                f.write(f"💻 {ip} - {osname} (Accuracy: {acc}%)\n")
            f.write("\n--- OTHER OS HOSTS DETECTED ---\n")
            for ip, osname, acc in other_hosts:
                f.write(f"🧹 {ip} - {osname} (Accuracy: {acc}%)\n")

        f.write("\n--- RAW NMAP OUTPUTS ---\n")
        f.write(raw_outputs)
        f.write(f"\nTotal Hosts Up in {subnet}: {total_up}\n")

    print(f"✅ Scan complete for subnet {subnet}, saved to {filename}")


def scan_multiple_subnets(subnet_list, output_path, custom_args):
    # Check if custom_args contains '-O'
    show_os_sections = '-O' in custom_args

    for subnet in subnet_list:
        try:
            ipaddress.ip_network(subnet, strict=False)
            detect_os_bulk(subnet, output_path, custom_args, show_os_sections)
        except ValueError as e:
            print(f"❌ Invalid subnet/IP '{subnet}': {e}")


def extract_subnets_from_file(filepath):
    subnets = []
    if filepath.lower().endswith('.xlsx'):
        df = pd.read_excel(filepath)
        for col in df.columns:
            subnets.extend(df[col].dropna().astype(str).tolist())
    elif filepath.lower().endswith('.txt'):
        with open(filepath, 'r') as f:
            subnets = [line.strip() for line in f if line.strip()]
    else:
        print("❌ Unsupported file format. Use .xlsx or .txt only.")
    return subnets


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🔍 Advanced Nmap OS/Vuln Detection Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--ip", help="Comma-separated IPs/Subnets (e.g., 192.168.1.0/24,10.0.0.0/25)")
    group.add_argument("-f", "--file", help="Excel (.xlsx) or Text (.txt) file with subnets")

    parser.add_argument("-o", "--output", required=True, help="Output folder for result .txt files")
    parser.add_argument("-c", "--custom", required=True, help="Custom Nmap arguments (e.g., \"-sV --script vuln -O -p-\")")

    args = parser.parse_args()

    if args.ip:
        ip_list = [ip.strip() for ip in args.ip.split(',') if ip.strip()]
    else:
        ip_list = extract_subnets_from_file(args.file)

    scan_multiple_subnets(ip_list, args.output, args.custom)
