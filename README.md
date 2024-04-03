# midterm-broqueza-sangreo

by [Althea Irish Sangreo](https://www.facebook.com/altheairish.sangreo) and [Marisol Broqueza](https://www.facebook.com/marisol.broqueza)

## **Information Gathering** 
means gathering different kinds of information about the target. It is basically, the first step or the beginning stage of Ethical Hacking, where the penetration testers or hackers (both black hat or white hat) tries to gather all the information about the target, in order to use it for Hacking. To obtain more relevant results, we have to gather more information about the target to increase the probability of a successful attack.

* ### [**AMASS**](https://www.kali.org/tools/amass/)
  is a tool to help information security professionals perform network mapping of attack surfaces and perform external asset discovery. Amass uses open-source data collection and active identification techniques to do this. This tool focuses on discovering and removing DNS, HTTP and SSL/TLS data. It should be noted that Amass provides several integrations with various API services such as the Security Trails API. It also scrapes the internet’s cache of forgotten data using various web archiving engines.

# COMMAND EXAMPLE: 
```bash
amass enum -d example.com
```
* ### [**Dmitry**](https://www.geeksforgeeks.org/dmitry-passive-information-gathering-tool-in-kali-linux/)
  is a free and open-source tool available on GitHub. The tool is used for information gathering. You can download the tool and install in your Kali Linux. Dmitry stands for DeepMagic Information Gathering Tool. It’s a command-line tool Using Dmitry tool You can collect information about the target, this information can be used for social engineering attacks. It can be used to gather a number of valuable pieces of information. LEGION(ROOT) This package contains an open source, easy-to-use, super-extensible and semi-automated network penetration testing tool that aids in discovery, reconnaissance and exploitation of information systems. Legion tool is a super-extensible and semi-automated network penetration testing framework. Legion is very easy to operate. MALTEGO (INSTALLER) Maltego is an open source intelligence and forensics application. It will offer you timous mining and gathering of information as well as the representation of this information in a easy to understand format.

# COMMAND EXAMPLE: 
```bash
dmitry -iwnp -t 7 host.net
```

* ### [**LEGION(ROOT)**](https://www.geeksforgeeks.org/legion-tool-in-kali-linux/)
  This package contains an open source, easy-to-use, super-extensible and semi-automated network penetration testing tool that aids in discovery, reconnaissance and exploitation of information systems.
Legion tool is a super-extensible and semi-automated network penetration testing framework. Legion is very easy to operate.


* ### [**MALTEGO (INSTALLER)**](https://www.geeksforgeeks.org/maltego-tool-in-kali-linux/)
   is an open-source intelligence and forensics application. It offers timely mining and gathering of information as well as the representation of this information in an easy-to-understand format.
  * It is used for gathering information for security-related work.
  * It will save your time and make your work smarter and more accurate.
  * It will help you in the thinking process by demonstrating connected links between all the searched items.
  * If you want to get hidden information, Maltego can help you discover it.


* ### [**NET DISCOVER**](https://www.kali.org/tools/netdiscover/)
  is an active/passive address reconnaissance tool, mainly developed for those wireless networks without dhcp server, when you are wardriving. It can be also used on hub/switched networks.
Netdiscover can also be used to inspect your network ARP traffic, or find network addresses using auto scan mode, which will scan for common local networks. Netdiscover uses the OUI table to show the vendor of the each MAC address discovered and is very useful for security checks or in pentests.


* ### [**NMAP**](https://linuxconfig.org/introduction-to-nmap-on-kali-linux)
   Nmap is a powerful tool for discovering information about machines on a network or the Internet. It allows you to probe a machine with packets to detect everything from running services and open ports to the operating system and software versions. It is also a powerful tool for finding open ports, examining hosts, and extracting useful information about the services that each port uses.


* ### [**RECON-NG**](https://kali.org/tools/recon-ng/)
  Recon-ng is a full-featured Web Reconnaissance framework written in Python. Complete with independent modules, database interaction, built in convenience functions, interactive help, and command completion, Recon-ng provides a powerful environment in which open source web-based reconnaissance can be conducted quickly and thoroughly.
This tool can be used to get information about our target(domain). The interactive console provides a number of helpful features, such as command completion and contextual help. Recon-ng is a Web Reconnaissance tool written in Python. It has so many modules, database interaction, built-in convenience functions, interactive help, and command completion, Recon-ng provides a powerful environment in which open source web-based reconnaissance can be conducted, and we can gather all information.


* ### [**SPIDER FOOT**](https://www.kali.org/tools/spiderfoot/)
   This package contains an open source intelligence (OSINT) automation tool. Its goal is to automate the process of gathering intelligence about a given target, which may be an IP address, domain name, hostname, network subnet, ASN, e-mail address or person’s name. SpiderFoot can be used offensively, i.e. as part of a black-box penetration test to gather information about the target, or defensively to identify what information you or your organisation are freely providing for attackers to use against you.
  
## **Vulnerability Analysis**

* ## [**LEGION (ROOT)**]()
  This package contains an open source, easy-to-use, super-extensible and semi-automated network penetration testing tool that aids in discovery, reconnaissance and exploitation of information systems.
Legion tool is a super-extensible and semi-automated network penetration testing framework. Legion is very easy to operate.



* ## [**NIKTO**]()
  Nikto is a pluggable web server and CGI scanner written in Perl, using rfp’s LibWhisker to perform fast security or informational checks.
   Features:
    * Easily updatable CSV-format checks database
    * Output reports in plain text or HTML
    * Available HTTP versions automatic switching
    * Generic as well as specific server software checks
    * SSL support (through libnet-ssleay-perl)
    * Proxy support (with authentication)
    * Cookies support
 
  
* ## [**NMAP**]()
  Nmap is a powerful tool for discovering information about machines on a network or the Internet. It allows you to probe a machine with packets to detect everything from running services and open ports to the operating system and software versions. It is also a powerful tool for finding open ports, examining hosts, and extracting useful information about the services that each port uses.



* ## [**UNIX-PRIVESC-CHECK**]()
  Unix-privesc-checker is a script that runs on Unix systems (tested on Solaris 9, HPUX 11, Various Linuxes, FreeBSD 6.2). It tries to find misconfigurations that could allow local unprivileged users to escalate privileges to other users or to access local apps (e.g. databases).

  It is written as a single shell script so it can be easily uploaded and run (as opposed to un-tarred, compiled and installed). It can run either as a normal user or as root (obviously it does a better job when running as root because it can read more files).


  
## Web Application Analysis



* ## [**BURPSUITE**]()
  Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application’s attack surface, through to finding and exploiting security vulnerabilities.


  
* ## [**COMMIX**]()
  This package contains Commix (short for [comm]and [i]njection e[x]ploiter). It has a simple environment and it can be used, from web developers, penetration testers or even security researchers to test web applications with the view to find bugs, errors or vulnerabilities related to command injection attacks. By using this tool, it is very easy to find and exploit a command injection vulnerability in a certain vulnerable parameter or string. Commix is written in Python programming language.


  
* ## [**SKIPFISH**]()
  Skipfish is a free, open-source Automated Penetration Testing tool available on GitHub made for security researchers.  Skipfish is used for information gathering and testing the security of websites and web servers. Skipfish is the easiest and one of the best tools for penetration testing. It provides many integrated tools to perform penetration testing on the target system. This tool is also known as an active web application security reconnaissance tool. This tool functions and makes a map on the console of the targeted site using recursive crawl and dictionary-based probes. This tool gives us all the security checks that are active in the domain. Lastly, this tool generates a report which can be further used for security assessments.


  
* ## [**SQLMAP**]()
  SQLMAP is a database pentesting tool used to automate SQL Injection. Practically using sqlmap, we can dump a whole database from a vulnerable server. SQLMap is written in python and has got dynamic testing features. It can conduct tests for various database backends very efficiently. Sqlmap offers a highly flexible & modular operation for a web pentester. It can act as a basic fingerprinting tool and till upto a full database exploitation tool.


  
* ## [**WEBSHELLS**]()
  A web shell is a file that will be parsed and executed as code by a webserver, which sends the results of back to the originator of the web request. They are written in web programming languages such as PHP, Java, Perl and others. In this sense they are the same as the legitimate programs that power the dynamic websites we use every day.


  
* ## [**WPSCAN**]()
  Wpscan is a vulnerability scanning tool, which comes pre-installed in Kali Linux. This scanner tool scans for vulnerabilities in websites that run WordPress web engines. The wpscan tool itself isn’t a malicious tool, as it is only for reconnaissance against a particular site. However, a skilled hacker could use the information obtained from this tool to exploit your websites. Another feature of this tool is that it can, for instance, perform brute force attacks on the supplied URL thus, it is highly recommended to not use the tool (if you are trying to exploit a WordPress running website) on a site, you do not own or have authorization to pentesting.


  
## Database Assessment



* ## [**SQLite Database Browser**]()
  SQLite is an Open-Source database program that uses a sub-set of the SQL database descriptor language. Databases are useful for collecting similar bundles of information in one place, a database. SQL is a well known open-standard. The database query language is then able to send queries to extract particular data from the database, or to select all data.


  
* ## [**SQLMAP**]()
  SQLMAP is a database pentesting tool used to automate SQL Injection. Practically using sqlmap, we can dump a whole database from a vulnerable server. SQLMap is written in python and has got dynamic testing features. It can conduct tests for various database backends very efficiently. Sqlmap offers a highly flexible & modular operation for a web pentester. It can act as a basic fingerprinting tool and till upto a full database exploitation tool.


  
## Password Attacks



* ## [**CEWL**]()
  CeWL (Custom Word List generator) is a ruby app which spiders a given URL, up to a specified depth, and returns a list of words which can then be used for password crackers such as John the Ripper. Optionally, CeWL can follow external links. CeWL can also create a list of email addresses found in mailto links. These email addresses can be used as usernames in brute force actions.



  * ## [**CRUNCH**](https://www.kali.org/tools/crunch/)
    Crunch is a wordlist generator where you can specify a standard character set or any set of characters to be used in generating the wordlists. The wordlists are created through combination and permutation of a set of characters. You can determine the amount of characters and list size.

















































