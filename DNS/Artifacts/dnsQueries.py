import dns.resolver
import csv
import dns.exception

def query_domain(resolver, domain_name):
    try:
        answers = resolver.resolve(domain_name, 'A')
        ip_list = [rdata.address for rdata in answers.rrset]
        ip_string = " ".join(ip_list)
        return ip_string, answers.ttl
    except (dns.exception.DNSException):
        return "", -1

INPUT_CSV = '../RawData/top500.csv'
OUTPUT_CSV = '../RawData/dns_query_results.csv'

carleton_resolver = dns.resolver.make_resolver_at('137.22.1.7')
google_resolver = dns.resolver.make_resolver_at('8.8.8.8')

with open(INPUT_CSV, 'r') as infile, \
     open(OUTPUT_CSV, 'w', newline='') as outfile:
    
    csv_reader = csv.reader(infile)
    csv_writer = csv.writer(outfile)
    
    csv_writer.writerow([
        'domain_name', 
        'Carleton_response_addresses', 
        'Google_response_addresses', 
        'TTL_Carleton', 
        'TTL_Google'
    ])
    
    next(csv_reader) # Skip header row of input

    for row in csv_reader:
        domain_name = row[0] 
        
        carleton_ips, carleton_ttl = query_domain(carleton_resolver, domain_name)
        google_ips, google_ttl = query_domain(google_resolver, domain_name)
        
        csv_writer.writerow([
            domain_name,
            carleton_ips,
            google_ips,
            carleton_ttl,
            google_ttl
        ])