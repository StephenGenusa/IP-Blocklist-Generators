#!/usr/bin/env python

import socket, sys

#http://stackoverflow.com/questions/3462784/how-to-check-if-a-string-matches-an-ip-adress-pattern-in-python
def isgoodipv4(s):
    pieces = s.split('.')
    if len(pieces) != 4: return False
    try: return all(0<=int(p)<256 for p in pieces)
    except ValueError: return False

if len(sys.argv) == 1:
    print ("Usage: [title] [input file name] [output file name]")
else:
    #print (sys.argv[1], sys.argv[2], sys.argv[3])
    #print(len(sys.argv))
    if len(sys.argv) == 4:
        text_file = open(sys.argv[2], "w")
        text_file.write("############################################\n")
        text_file.write("### " + sys.argv[1] + "\n")
        text_file.write("############################################\n")
        text_file.write("#\n")
        
    with open(sys.argv[3]) as f:
        for line in f:
            #line = ""
            try:
                print "Looking up", line.strip()
                if isgoodipv4(line.strip()):
                    new_entry = line.strip() + ':' + line.strip() + '-' + line.strip()
                else:
                    data = socket.gethostbyname_ex(line.strip())
                    dns_values = data[2]
                    #print("DNS Values=", dns_values)
                    for dns_value in dns_values:
                        new_entry = line.strip() + ':' + dns_value + '-' + dns_value
                        print "          ", new_entry
                        if len(sys.argv) == 4:
                            text_file.write(new_entry + "\n")
                    #print (dns_values) 
            except Exception, err:
                pass
    print("\n\n")
if len(sys.argv) == 4:
    text_file.close()
        
