import pandas as pd
import json
import sys
from collections import Counter

def load_log_data(logfile):
    try:
        with open(logfile, 'r') as file:
            logs = [json.loads(line.strip()) for line in file]
        return pd.DataFrame(logs)
    except Exception as e:
        print(f"Error loading log file: {e}")
        return None

def analyze_failed_logins(df):
    failed_logins = df[df['event'] == 'login_failed']
    ip_counts = Counter(failed_logins['source_ip'])
    
    for ip, count in ip_counts.items():
        if count > 3:
            print(f"Suspicious activity detected from IP {ip}: {count} failed login attempts")

def analyze_unusual_login_times(df):
    df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
    unusual_hours = df[(df['hour'] < 6) | (df['hour'] > 22)]
    if not unusual_hours.empty:
        print("Logins at unusual hours detected:")
        print(unusual_hours[['timestamp', 'source_ip', 'event', 'username']])

def main():
    if len(sys.argv) < 3 or sys.argv[1] != '--logfile':
        print("Usage: python parser.py --logfile <path_to_logfile>")
        return

    logfile = sys.argv[2]
    df = load_log_data(logfile)

    if df is not None:
        print("Analyzing failed login attempts...")
        analyze_failed_logins(df)
        
        print("\nAnalyzing logins during unusual hours...")
        analyze_unusual_login_times(df)

if __name__ == "__main__":
    main()
