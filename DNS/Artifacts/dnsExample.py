''' Sample code written by Matt Lepinski '''

import dns.name
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver

# This constructs a domain name object
domain = dns.name.from_text('www.cia.gov')

# This is a local Carleton DNS Server
name_server = '137.22.1.7'

# An 'A' request asks for the IPv4 address for a domain name
# We could change this if we wanted to make a different request like AAAA
request_type = dns.rdatatype.A

my_query = dns.message.make_query(domain, request_type)

# This sends a raw DNS query (using UDP)
response = dns.query.udp( my_query, name_server)

print(response)

# ------------------------------

# Depending on what you are doing, it can be easier to create a resolver object
#   ... The resolver object has a resolve method for acquiring DNS answers

carleton_resolver = dns.resolver.make_resolver_at('137.22.1.7')

answers = carleton_resolver.resolve('www.cia.gov', 'A')

print( "The return type for the resolve function", type(answers) )

print( "Time to Live: ", answers.ttl)

# The full response
print( answers.response)

# The rrset property contains the IP addresses returned by the A query
for rdata in answers.rrset:
    print( "Answer address: ", rdata.address )
