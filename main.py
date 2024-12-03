import re
import csv
from collections import defaultdict

# Constants
FAILED_LOGIN_THRESHOLD = 10  # Configurable threshold for failed login attempts

# Function to parse log file and extract required data
def analyze_log_file(log_file):
    ip_requests = defaultdict(int)
    endpoints = defaultdict(int)
    failed_logins = defaultdict(int)

    # Regular expressions for parsing log entries
    log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*\] "(?P<method>\w+) (?P<endpoint>/\S+) HTTP/\S+" (?P<status>\d+)')
    failed_login_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*\] ".+" 401 .+"Invalid credentials"')

    # Open and read log file
    with open(log_file, 'r') as file:
        for line in file:
            # Match regular log entry
            match = log_pattern.match(line)
            if match:
                ip = match.group('ip')
                endpoint = match.group('endpoint')
                status = match.group('status')

                # Count requests per IP address
                ip_requests[ip] += 1

                # Count accesses per endpoint
                endpoints[endpoint] += 1

            # Check for failed login attempts
            failed_login_match = failed_login_pattern.match(line)
            if failed_login_match:
                ip = failed_login_match.group('ip')
                failed_logins[ip] += 1

    return ip_requests, endpoints, failed_logins

# Function to display and save results
def display_and_save_results(ip_requests, endpoints, failed_logins):
    # Sort requests per IP by count
    sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)

    # Most accessed endpoint
    most_accessed_endpoint = max(endpoints.items(), key=lambda x: x[1])

    # Suspicious activity based on failed login attempts
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

    # Display Results
    print("IP Address           Request Count")
    for ip, count in sorted_ip_requests:
        print(f"{ip:20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:20} {count}")

    # Save Results to CSV
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        fieldnames = ['IP Address', 'Request Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for ip, count in sorted_ip_requests:
            writer.writerow({'IP Address': ip, 'Request Count': count})

        writer.writerow({})  # Empty row for separation

        fieldnames = ['Endpoint', 'Access Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({'Endpoint': most_accessed_endpoint[0], 'Access Count': most_accessed_endpoint[1]})

        writer.writerow({})  # Empty row for separation

        fieldnames = ['IP Address', 'Failed Login Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for ip, count in suspicious_ips.items():
            writer.writerow({'IP Address': ip, 'Failed Login Count': count})

# Main function to process the log file
def main():
    log_file = 'sample.log'  # Path to the log file
    ip_requests, endpoints, failed_logins = analyze_log_file(log_file)
    display_and_save_results(ip_requests, endpoints, failed_logins)

if __name__ == "__main__":
    main()
