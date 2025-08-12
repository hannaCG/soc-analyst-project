"""
Login Attempts Analysis Script
-------------------------------
This script parses an SSH authentication log file, extracts relevant data (IP address, username, timestamp, authentication status), and generates visualizations of login attempts.

Author: Ana Cano
Date: 2025-08-06
"""

# ============================
# 1. IMPORT LIBRARIES
# ============================
import pandas as pd
import re
import os
import matplotlib.pyplot as plt
import seaborn as sns

# ============================
# 2. PATHS & CONFIGURATION
# ============================
# Get script directory for dynamic absolut paths
script_dir = os.path.dirname(os.path.abspath(__file__))

# Define input (log file) and output directories
log_path = os.path.join(script_dir, '..', 'data', 'auth_sample.log')
output_dir = os.path.join(script_dir, '..', 'output')

# Ensure output directory exists
os.makedirs(output_dir, exist_ok=True)

# REGEX pattern for parsing log lines
pattern = r'(?P<date>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) .*sshd.*: (?P<status>Failed|Accepted) password for (invalid user )?(?P<user>\w+) from (?P<ip>[\d\.]+)'


# ============================
# 3. READ & PARSE LOG FILE
# ============================
log_entries = []

with open(log_path, 'r', encoding = 'utf-8')as file:
    for line in file:
        match = re.search(pattern, line)
        if match:
            log_entries.append({
                'date': match.group('date'),
                'status': match.group('status'),
                'user': match.group('user'),
                'ip': match.group('ip'),
            })


# ============================
# 4. CREATE A DATAFRAME
# ============================
df = pd.DataFrame(log_entries)
print(df.head()) # Display first rows for verification

# Save parse Log data to CSV
df.to_csv(os.path.join(output_dir, 'log_entries.csv'), index=False)


# ============================
# 5. DEFINE A COLOR PALETTE
# ============================
# Define a color palette (10 colors for top categories)
palette_colors = sns.color_palette('crest', n_colors=10)


# ============================
# 6. VISUALIZATIONS
# ============================
# Chart 1 - Top 10 IPs by Login Attempts
plt.figure(figsize=(12, 6))
sns.countplot(data=df, x='ip', order=df['ip'].value_counts().index[:10], palette=palette_colors)
plt.xticks(rotation=45) 
plt.title('Top 10 IPs by Login Attempts')
plt.xlabel('IP Address')
plt.ylabel('Number of attempts')
plt.tight_layout()
# Save in PNG, PDF, and SVG
plt.savefig(os.path.join(output_dir, 'top_ips.png'))
plt.savefig(os.path.join(output_dir, 'top_ips.pdf'))
plt.savefig(os.path.join(output_dir, 'top_ips.svg'))
plt.show()

# Chart 2 - Login Attempts by Hour of Day
df['hour'] = df['date'].str.extract(r'(\d{2}):\d{2}:\d{2}')
plt.figure(figsize=(10, 5))
sns.countplot(data=df, x='hour', order=sorted(df['hour'].unique()), palette=palette_colors)
plt.title('Login Attempts by Hour of Day')
plt.xlabel('Hour (24h format)')
plt.ylabel('Number of Attempts')
plt.tight_layout()
# Save in PNG, PDF, and SVG
plt.savefig(os.path.join(output_dir, 'login_attempts_by_hour.png'))
plt.savefig(os.path.join(output_dir, 'login_attempts_by_hour.pdf'))
plt.savefig(os.path.join(output_dir, 'login_attempts_by_hour.svg'))
plt.show()

# Chart 3 - Most Targeted Usernames
plt.figure(figsize=(12, 6))
sns.countplot(data=df, x='user', order=df['user'].value_counts().index[:10], palette=palette_colors)
plt.title('Top 10 Targeted Usernames')
plt.xlabel('Username')
plt.ylabel('Number of Attempts')
plt.xticks(rotation=45)
plt.tight_layout()
# Save in PNG, PDF, and SVG
plt.savefig(os.path.join(output_dir, 'targeted_usernames.png'))
plt.savefig(os.path.join(output_dir, 'targeted_usernames.pdf'))
plt.savefig(os.path.join(output_dir, 'targeted_usernames.svg'))
plt.show()

# Chart 4 - Authentication Status Distribution
plt.figure(figsize=(8, 5))
sns.countplot(data=df, x='status', hue='status', order=['Accepted', 'Failed'], palette='Set2', legend=False)
plt.title('Authentication Status Distribution')
plt.xlabel('Authentication Result')
plt.ylabel('Number of Attempts')
plt.tight_layout()
# Save in PNG, PDF, and SVG
plt.savefig(os.path.join(output_dir, 'auth_status_distribution.png'))
plt.savefig(os.path.join(output_dir, 'auth_status_distribution.pdf'))
plt.savefig(os.path.join(output_dir, 'auth_status_distribution.svg'))
plt.show()

print(f'✅ All charts and CSV saved in: {output_dir}')