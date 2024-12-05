import re
import csv
from collections import defaultdict

FAILED_LOGIN_THRESHOLD = 10

IP_PATTERN = r'(\d+\.\d+\.\d+\.\d+)'
ENDPOINT_PATTERN = r'\"(?:GET|POST) ([^\s]+)'
FAILED_LOGIN_PATTERN = r' 401 '

def parse_log_file(log_file):
    with open(log_file, 'r') as file:
        return file.readlines()

def count_requests_per_ip(log_entries):
    ip_count = defaultdict(int)
    for entry in log_entries:
        ip_match = re.search(IP_PATTERN, entry)
        if ip_match:
            ip_address = ip_match.group(1)
            ip_count[ip_address] += 1
    return ip_count

def most_accessed_endpoint(log_entries):
    endpoint_count = defaultdict(int)
    for entry in log_entries:
        endpoint_match = re.search(ENDPOINT_PATTERN, entry)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_count[endpoint] += 1
    most_accessed = max(endpoint_count, key=endpoint_count.get, default=None)
    return most_accessed, endpoint_count[most_accessed]

def detect_suspicious_activity(log_entries, threshold=FAILED_LOGIN_THRESHOLD):
    failed_login_count = defaultdict(int)
    for entry in log_entries:
        if re.search(FAILED_LOGIN_PATTERN, entry):
            ip_match = re.search(IP_PATTERN, entry)
            if ip_match:
                ip_address = ip_match.group(1)
                failed_login_count[ip_address] += 1

    suspicious_activity = {ip: count for ip, count in failed_login_count.items() if count > threshold}
    return suspicious_activity

def save_results_to_csv(ip_counts, most_accessed, failed_logins):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        fieldnames = ['IP Address', 'Request Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for ip, count in ip_counts.items():
            writer.writerow({'IP Address': ip, 'Request Count': count})

        writer.writerow({})

        writer.writerow({'IP Address': 'Most Accessed Endpoint', 'Request Count': most_accessed[0]})
        writer.writerow({'IP Address': 'Access Count', 'Request Count': most_accessed[1]})

        writer.writerow({})

        writer.writerow({'IP Address': 'IP Address', 'Request Count': 'Failed Login Attempts'})
        for ip, count in failed_logins.items():
            writer.writerow({'IP Address': ip, 'Request Count': count})

def display_results(ip_counts, most_accessed, failed_logins):
    """Displays the results on the terminal."""
    print("IP Address           Request Count")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in sorted(failed_logins.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:20} {count}")

def main():
    log_entries = parse_log_file('sample.log')

    ip_counts = count_requests_per_ip(log_entries)

    most_accessed = most_accessed_endpoint(log_entries)

    failed_logins = detect_suspicious_activity(log_entries)

    display_results(ip_counts, most_accessed, failed_logins)

    save_results_to_csv(ip_counts, most_accessed, failed_logins)

if __name__ == '__main__':
    main()
