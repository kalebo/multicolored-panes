import nmap
import os
import sys

if os.geteuid() != 0:
    raise EnvironmentError("TCP/IP fingerprinting (for OS scan) requires root privileges!")
    exit()

subnets = ' '.join(sys.argv[1:])

nm = nmap.PortScannerYield()

matches = set()
total = 0

for host, results in nm.scan(hosts=subnets, arguments='-O -F'):
    total += 1
    print("Checking host: {}... ".format(host), end='')
    #print(results)
    matched = False
    if results['scan'] != {}:
        if results['scan'][host]['osmatch'] != []: # Occurs when there are too many possible matches
            for osmatch in results['scan'][host]['osmatch']:
                if "Windows" in osmatch['name'] and int(osmatch['accuracy']) > 90:
                    matches.add(host)
                    matched = True
    print(matched)
    print("Found: {}/{}".format(len(matches), total), end = '\r')
print("Found {} Windows Machine(s) out of a total of {} addresses on the following hosts/subnet(s): {}".format(len(matches), total, subnets))
