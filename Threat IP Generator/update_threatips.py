#! /usr/bin/env python

"""
Threat IP Blocklist Builder
Generate Blocklist for Current Threats
March 2015 by Stephen Genusa
http://development.genusa.com
"""


import re
import sys
import urllib2



def urlopen(url):
    """ urlopen behaves exactly like urllib2.urlopen, but injects a user-agent header
    """
    headers = {'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.154 Safari/537.36'}
    req = urllib2.Request(url, None, headers)
    return urllib2.urlopen(req)


def strip_leading_zeros(ip_address):
    """Strip leading zeros from each IP octet and
       return empty string if IP == 0.0.0.0
    """
    if ip_address != '':
        ip_addr_oct =  ip_address.split('.')
        ip_address = str(int(ip_addr_oct[0])) + '.' + str(int(ip_addr_oct[1])) + '.' + \
               str(int(ip_addr_oct[2])) + '.' + str(int(ip_addr_oct[3]))
        if ip_address == '0.0.0.0': 
            ip_address = ''
    return ip_address


def write_file_header():
    """Write the file header showing sources
    """
    of.writelines('''#####################################################
### Threat IPs and Malware Domain IPs
### https://isc.sans.edu/api/topips/records/1000
### https://www.dshield.org/ipsascii.html
### http://www.malwaredomainlist.com/hostslist/ip.txt
### http://www.malwaregroup.com/ipaddresses/malicious
#####################################################
#
''')
    
    

def build_threatlist_from_url(message, http_url, item_prefix, of, ip_regex):
    """Download a URL, parse for IPs and add to the output file
    """
    print "Building", message
    threat_html = urlopen(http_url).read()
    ip_addresses = ip_regex.findall(threat_html)
    ip_address_list = []
    for ip_address in ip_addresses:
        ip_address = strip_leading_zeros(ip_address)
        if ip_address != '' and ip_address not in ip_address_list:
            ip_address_list.append(ip_address)
        threat_counter = 0
    for ip_address in ip_address_list:
        threat_counter += 1
        of.write('Threat IP ' + item_prefix + ' ' + str(threat_counter).rjust(6, '0') + ':' + ip_address + '-' + ip_address + '\n')



def main():
    # Open the output file and write the header
    of=open('threat_ips.txt', 'w')
    # Compile basic IP regex
    ip_regex = re.compile(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})')
    # Parse each of the URLs
    build_threatlist_from_url("SANS Threat IP List", 'https://isc.sans.edu/api/topips/records/1000', '(SANS)', of, ip_regex) 
    build_threatlist_from_url("DShield Threat IP List", 'http://www.dshield.org/ipsascii.html?limit=10000', '(DShield)', of, ip_regex) 
    build_threatlist_from_url("Malware Domain Threat IP List", 'http://www.malwaredomainlist.com/hostslist/ip.txt', '(Malware)', of, ip_regex) 
    build_threatlist_from_url("Malicious Threat IP List", 'http://www.malwaregroup.com/ipaddresses/malicious', '(Malicious)', of, ip_regex) 
    of.close()
    print "Done"

    
if __name__ == "__main__":
    main()
