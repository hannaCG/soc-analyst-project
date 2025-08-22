import csv
from datetime import datetime

print("Script is running")

def alert_on_5_consecutive_failures(csv_path):
    with open(csv_path, newline='') as f:
        reader = csv.DictReader(f)
        logs = list(reader)

    print(f"Total logs parsed: {len(logs)}")
    print("First 5 entries:")
    for i, log in enumerate(logs[:5], 1):
        print(f"{i}: {log}")

    for log in logs:
        log['date'] = datetime.strptime(log['date'], '%b %d %H:%M:%S')

    logs.sort(key=lambda x: x['date'])

    fail_streak = {}
    alert_found = False
    for log in logs:
        ip = log['ip']
        status = log['status'].lower()

        if ip not in fail_streak:
            fail_streak[ip] = 0

        if status == 'failed':
            fail_streak[ip] += 1
            if fail_streak[ip] == 5:
                print(f'ALERT: IP {ip} has failed 5 consecutive times')
                alert_found = True
        else:
            fail_streak[ip] = 0

    if not alert_found:
        print("No IPs found with 5 consecutive failures.")

# Path
csv_file_path = 'C:/Users/anamc/Documents/3. Ciberseguridad/Proyecto_SOC_Analyst/output/log_entries.csv'
alert_on_5_consecutive_failures(csv_file_path)