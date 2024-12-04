import re
import csv
from collections import Counter, defaultdict

def parse_log_file(file_path):
    ip_requests = Counter()
    endpoints = Counter()
    failed_logins = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1

            # Extract endpoint (e.g., /home or /login)
            endpoint_match = re.search(r'\"(?:GET|POST|PUT|DELETE) ([^\s]+)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoints[endpoint] += 1

            # Detect failed login attempts (status code 401 or "Invalid credentials")
            if '401' in line or 'Invalid credentials' in line:
                if ip_match:
                    failed_logins[ip] += 1

    return ip_requests, endpoints, failed_logins

def save_results_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write requests per IP
        writer.writerow(['Requests Per IP','',''])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.most_common():
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

# To detect 
def process_failed_login_threshold(failed_logins, threshold):
    print("\nIPs exceeding the threshold of failed attempts:")
    exceeding_threshold = False
    for ip, count in failed_logins.items():
        if count > threshold:
            print(f"IP: {ip}, Failed Attempts: {count}")
            exceeding_threshold = True

    # If no IP exceeds the threshold
    if not exceeding_threshold:
        print("NIL")

def main():
    log_file_path = 'sample.log'  # Log file path
    threshold = 10  # Configurable threshold

    # Parse log file
    ip_requests, endpoints, failed_logins = parse_log_file(log_file_path)

    # Display requests per IP in formatted output
    print("\nIP Address           Request Count")
    print("-" * 35)
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20} {count}")

    # Identify the most accessed endpoint
    if endpoints:
        most_accessed_endpoint = endpoints.most_common(1)[0]
        print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    else:
        most_accessed_endpoint = ("None", 0)
        print("\nNo endpoints found.")

    # Display detected suspicious activity
    print("\nIP Address           Failed Atempts")
    print("-" * 37)
    for ip, count in failed_logins.items():
        print(f"{ip:<20} {count}")
    process_failed_login_threshold(failed_logins, threshold)

    # Save results to CSV
    save_results_to_csv(ip_requests, most_accessed_endpoint, failed_logins)
    print("\nResults saved to log_analysis_results.csv\n")

if __name__ == '__main__':
    main()
