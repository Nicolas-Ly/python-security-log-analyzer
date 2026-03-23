from collections import Counter

#accessing the dns and proxy logs files
dns_file = open("logs/dns.log", "r")
proxy_file = open("logs/proxy.log", "r")

# -----------------------------------------------
# Analyzing the DNS logs for malicious domains
# stores the domains
domains = []

for line in dns_file:
    # used to split lines in dns file
    parts = line.split()
    # gets the domain using parts variable to split specific parts of the list
    domain = parts[3].split("=")[1]
    #adds the found domain to domains list
    domains.append(domain)

dns_file.close()
# gets the amount of the different domains
counts = Counter(domains)

# Domains to watch out for
suspicious_domains = [
   "malicious-domain.ru",
   "strange-domain.xyz"
]


for domain, count in counts.items():
    print(domain,":", count)

if any(domain in domains for domain in suspicious_domains):
    for domain, count in counts.items():
        if domain in suspicious_domains:
            print("ALERT: Suspocious domain detected:", domain)
        elif count > 3:
            print("ALERT: Possible DNS beaconing:\n", domain)
else:
    print("No suspicious domains found.\n")


# -----------------------------------------------
# Analyzing the proxy logs to detect malicious traffic

print("\nNow analyzing Proxy Logs...")
print("Logs Accessed:")

urls= []

for line in proxy_file:
    parts = line.split()

    url = parts[3].split("=")[1]
    urls.append(url)
    print("URL Accessed:", url)

proxy_file.close()

print("\nLooking for malicious traffic:")

for url in urls:
    for bad_domain in suspicious_domains:
        if bad_domain in url:
            print("ALERT: Malicious proxy traffic:", url)


# -------------------------------------------
# Writing dns and proxy findings to the report
report = open("report.txt", "w")

report.write("Security Analysis Report\n")
report.write("------------------------\n")

# Wrtiting dns findings
report.write("DNS:\n")
report.write("------------------\n")
for domain, count in counts.items():
    if domain in suspicious_domains:
        report.write(f"Suspicious DNS Query: {domain}\n")


# Writing proxy findings
report.write("\nProxy:\n")
report.write("------------------\n")
for url in urls:
    for malicious in suspicious_domains:
        if malicious in url:
            report.write(f"Malicious Proxy Traffic: {url}\n")
report.close