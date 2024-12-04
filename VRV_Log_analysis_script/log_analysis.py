import csv
from collections import defaultdict

# Constants
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10

def count_requests_per_ip(log_file):
    ip_counts = defaultdict(int)
    with open(log_file, 'r') as file:
        for line in file:
            ip = line.split(' ')[0]
            ip_counts[ip] += 1
    return dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True))

def most_frequent_endpoint(log_file):
    endpoint_counts = defaultdict(int)
    with open(log_file, 'r') as file:
        for line in file:
            endpoint = line.split(' ')[6]
            endpoint_counts[endpoint] += 1
    most_accessed = max(endpoint_counts.items(), key=lambda x: x[1])
    return most_accessed

def detect_suspicious_activity(log_file, threshold):
    failed_logins = defaultdict(int)
    with open(log_file, 'r') as file:
        for line in file:
            if '401' in line or "Invalid credentials" in line:
                ip = line.split(' ')[0]
                failed_logins[ip] += 1
    return {ip: count for ip, count in failed_logins.items() if count >= threshold}

def save_to_csv(ip_counts, most_accessed, suspicious_ips):
    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # IP Request Count Section
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        writer.writerow([])

        # Most Accessed Endpoint Section
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])

        # Suspicious Activity Section
        writer.writerow(["IP Address", "\tFailed Login Attempts"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    ip_counts = count_requests_per_ip(LOG_FILE)
    most_accessed = most_frequent_endpoint(LOG_FILE)
    suspicious_ips = detect_suspicious_activity(LOG_FILE, FAILED_LOGIN_THRESHOLD)

    # Display results in terminal
    print("Requests per IP Address:")
    print("IP Address \t Request Count")
    for ip, count in ip_counts.items():
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address \t  Failed Login Times")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")

    # Save results to CSV
    save_to_csv(ip_counts, most_accessed, suspicious_ips)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()



