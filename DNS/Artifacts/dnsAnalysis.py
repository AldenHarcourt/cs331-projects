import csv
import statistics

INPUT_CSV = '../RawData/dns_query_results.csv'

# --- Initialize counters and lists ---
total_rows = 0
carleton_failures = 0
google_failures = 0
different_failure_sites = []

carleton_addr_counts = []
google_addr_counts = []

different_ips_count = 0
common_success_count = 0

carleton_ttls_valid = []
google_ttls_valid = []
# New counters for high TTLs
carleton_high_ttl_count = 0
google_high_ttl_count = 0

with open(INPUT_CSV, 'r') as infile:
    csv_reader = csv.reader(infile)
    header = next(csv_reader) # Skip header

    idx_domain = header.index('domain_name')
    idx_c_addr = header.index('Carleton_response_addresses')
    idx_g_addr = header.index('Google_response_addresses')
    idx_c_ttl = header.index('TTL_Carleton')
    idx_g_ttl = header.index('TTL_Google')

    for row in csv_reader:
        total_rows += 1
        
        domain = row[idx_domain]
        c_addr = row[idx_c_addr]
        g_addr = row[idx_g_addr]
        c_ttl = int(row[idx_c_ttl])
        g_ttl = int(row[idx_g_ttl])

        c_failed = (c_ttl == -1)
        g_failed = (g_ttl == -1)
        
        # ---Failure Percentage---
        if c_failed:
            carleton_failures += 1
        if g_failed:
            google_failures += 1
        if c_failed != g_failed:
            different_failure_sites.append(domain)
        
        # ---Address Counts and TTLs (if successful)---
        if not c_failed:
            carleton_ttls_valid.append(c_ttl)
            if c_ttl > 300:
                carleton_high_ttl_count += 1

            carleton_addr_counts.append(len(c_addr.split(' ')))
            
        if not g_failed:
            google_addr_counts.append(len(g_addr.split(' ')))
            google_ttls_valid.append(g_ttl)
            if g_ttl > 300:
                google_high_ttl_count += 1
            
        # ---Different IP Answers (if both successful---
        if not c_failed and not g_failed:
            common_success_count += 1

            c_set = set(c_addr.split(' '))
            g_set = set(g_addr.split(' '))
            if c_set != g_set:
                different_ips_count += 1



print("---Failure Stats---")
print(f"Carleton Fail %: {carleton_failures / total_rows * 100:.2f}")
print(f"Google Fail %: {google_failures / total_rows * 100:.2f}")
print(f"Sites w/ different failure: {len(different_failure_sites)}")
# Sites that failed one but not the other
if different_failure_sites:
    print("Sites that differed in failure:")
    for site in different_failure_sites:
        print(f"  - {site}")

print("\n---Address Count Stats---")
print(f"Carleton Addr Avg: {statistics.mean(carleton_addr_counts):.2f}")
print(f"Carleton Addr StdDev: {statistics.stdev(carleton_addr_counts):.2f}")
print(f"Google Addr Avg: {statistics.mean(google_addr_counts):.2f}")
print(f"Google Addr StdDev: {statistics.stdev(google_addr_counts):.2f}")

print("\n---Different IPs---")
print(f"Sites w/ different IPs: {different_ips_count}")

print("\n---TTL Stats---")
print("Carleton (All):")
print(f"  Avg: {statistics.mean(carleton_ttls_valid):.2f}")
print(f"  StdDev: {statistics.stdev(carleton_ttls_valid):.2f}")

print("\nGoogle (All):")
print(f"  Avg: {statistics.mean(google_ttls_valid):.2f}")
print(f"  StdDev: {statistics.stdev(google_ttls_valid):.2f}")

print("\n---TTL Counts Above 300s---")
print(f"Carleton: {carleton_high_ttl_count}")
print(f"Google: {google_high_ttl_count}")