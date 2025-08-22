import re
from collections import defaultdict, Counter
import os

# ---------------------------------------------------------
# Funciones de parseo y análisis
# ---------------------------------------------------------
def parse_logs(log_lines):
    """
    Extract IP addresses and authentication status from raw log lines.
    """
    log_entries = []
    for line in log_lines:
        match = re.search(r'(\w+\s+\d+\s+\d+:\d+:\d+).*?(Failed|Accepted).*?from\s+(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            date_str = match.group(1)
            status = match.group(2)
            ip = match.group(3)
            log_entries.append({"date": date_str, "status": status, "ip": ip})
    return log_entries


def detect_consecutive_failures(log_entries, threshold=5):
    """
    Detect IPs with N or more consecutive failed login attempts.
    """
    fail_streak = defaultdict(int)
    failure_counts = defaultdict(int)
    alerted_ips = set()

    for entry in log_entries:
        ip = entry["ip"]
        status = entry["status"].lower()

        if status == "failed":
            fail_streak[ip] += 1
            failure_counts[ip] += 1
            if fail_streak[ip] == threshold:
                alerted_ips.add(ip)
        else:
            fail_streak[ip] = 0  # reset streak on success
            
        
    # Build structured results
    results = []
    for ip in sorted(failure_counts.keys()):
        results.append({
            "ip": ip,
            "total_failures": failure_counts[ip],
            "alert_triggered": ip in alerted_ips
            })
    
    return results

# ---------------------------------------------------------
# Funciones de display
# ---------------------------------------------------------
def display_console_report(results):
    """
    Display results in a clean text-based table format.
    """
    print("\n" + '='*60)
    print(f"{'IP Address':<18}{'Total Failures':<18}{'Alert Triggered'}")
    print("="*60)

    for entry in results:
        alert_status = "🚨 YES" if entry["alert_triggered"] else "No"
        print(f"{entry['ip']:<18}{entry['total_failures']:<18}{alert_status}")

    print("="*60 + "\n")


def display_summary(log_entries, results, threshold=5):
    """"
    Display a clear SOC-style summary in console.
    """
    failed_ips = [entry["ip"] for entry in log_entries if entry["status"].lower() == "failed"]
    counter = Counter(failed_ips)

    print("="*50)
    print("                             DAILY SECURITY REPORT")
    print("="*50)
    print(f"Total logs processed: {len(log_entries)}")
    print(f"Unique IPs: {len(set([e['ip'] for e in log_entries]))}")
    print(f"Suspicius IPs: {sum(1 for ip, count in counter.items() if count >= threshold)}\n")

    print("Top Failed Logins:")
    for ip, count in counter.most_common(5):
        print(f" {ip} -> {count} fails")

        print("\nAlerts Triggered:")
        for entry in results:
            if entry["alert_triggered"]:
                print(f"   - ALERT: {entry['ip']} failed {entry['total_failures']} times (Threshold: {threshold})")
        
        print("="*50)


# ---------------------------------------------------------
# Función para exportar HTML
# ---------------------------------------------------------
def export_html_report(log_entries, results, output_path="docs/alerts_report.html", threshold=5):
    """
    Export results to HTML file with a summary and detailed table.
    """
    failed_ips = [entry["ip"] for entry in log_entries if entry["status"].lower() == "failed"]
    counter = Counter(failed_ips)

    total_logs = len(log_entries)
    unique_ips = len(set([e["ip"] for e in log_entries]))
    suspicious_ips = sum(1 for ip, count in counter.items() if count >= threshold)

    # Build HTML
    html_content = f"""
    <html>
    <head>
        <title> Alerts Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h2, h3 {{ text-align: center; }}
            table {{ border-collapse: collapse; width: 80%; margin: auto; }}
            th {{ background-color: #333; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .alert {{ color: red; font-weight: bold; }}
            .no-alert {{ color: green; }}
            .summary {{ width: 60%; margin: auto; margin-bottom: 30px; }}
            .summary td {{ text-align: left; padding: 5px; }}
        <style>
    </head>
    <body>
        <h2> SOC Analyst - Alerts Report</h2>

        <h3>📊 Summary</h3>
        <table class = "summary">
            <tr><td><b>Total logs processed: </b></td><td>{total_logs}</td></tr>
            <tr><td><b>Unique IPs:</b></td><td>{unique_ips}</td></tr>
            <tr><td><b>Suspicious IPs (≥ {threshold} fails):</b></td><td>{suspicious_ips}</td></tr>
        </table>

        <h3>Top Failed Logins</h3>
        <table class="summary">
    """

    for ip, count in counter.most_common(5):
        html_content += f"<tr><td>{ip}</td><td>{count} fails</td></tr>"

    html_content += """
        <table>

        <h3>Detailed Results</h3>
        <table>
            <tr>
                <th>IP Address</th>
                <th>Total Failures</th>
                <th>Alert Triggered</th>
            <tr>
        """
    
    for entry in results:
        alert_status = f"<span class='alert> 🚨 YES</span>" if entry["alert_triggered"] else "<span class='no-alert'>No<span>"
        html_content += f"""
            <tr>
                <td>{entry['ip']}</td>
                <td>{entry['total_failures']}</td>
                <td>{alert_status}</td>
            </tr>
        """

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        print(f"[+] HTML report generated at: {output_path}")

# -----------------------------
# Función para simular alertas por correo
# -----------------------------
def simulate_email_alert(ip, threshold=5):
    print(f"[SIMULATED] Email alert sent to: soc_analyst@example.com for IP {ip} (Threshold: {threshold})")


# ---------------------------------------------------------
# Bloque principal
# ---------------------------------------------------------
if __name__ == "__main__":
    # Read your real log file
    log_file_path = "C:/Users/anamc/Documents/3. Ciberseguridad/Proyecto_SOC_Analyst/data/auth_sample.log"

    with open(log_file_path, "r", encoding="utf-8") as file:
        real_logs = file.readlines()

    # Step 1: Parse
    parsed_entries = parse_logs(real_logs)

    # Step 2: Detect
    results = detect_consecutive_failures(parsed_entries)

    # Step 3: Display
    display_console_report(results)

    # Step 4: Display Summary
    display_summary(parsed_entries, results)

    # Step 5: Export to HTML with summary
    export_html_report(parsed_entries, results)

    # Send alerts for triggered IPs
    for entry in results:
        if entry["alert_triggered"]:
            simulate_email_alert(entry["ip"])