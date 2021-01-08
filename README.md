# Micro_Internship_Project
Burp Suite Extension

Extension for the application security testing software Burp Suite. The extension takes the host name from an HTTP request and performs a domain name system lookup to retrieve the corresponding IP addresses. This is displayed alongside the tool that made the HTTP request and a time stamp in a new custom tab within the Burp Suite UI. The host name and corresponding IP addresses are saved as key value pairs to a dictionary. Future request are checked against this dictionary. Upon unloading the extension the dictionary is saved to a text file (DNS_file.txt). This is then loaded the next time the extension is loaded to be used as a database.
