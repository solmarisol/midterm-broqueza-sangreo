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


* ## [**HASHCAT**](https://www.kali.org/tools/hashcat/)
  Hashcat supports five unique modes of attack for over 300 highly-optimized hashing algorithms. hashcat currently supports CPUs, GPUs, and other hardware accelerators on Linux, and has facilities to help enable distributed password cracking.


* ## [**HYDRA**](https://www.kali.org/tools/hydra/)
  Hydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.


* ## [**JOHN**](https://www.kali.org/tools/john/)
  John the Ripper is a tool designed to help systems administrators to find weak (easy to guess or crack through brute force) passwords, and even automatically mail users warning them about it, if it is desired.


* ## [**MEDUSA**](https://www.kali.org/tools/medusa/)
  Medusa is intended to be a speedy, massively parallel, modular, login brute-forcer. The goal is to support as many services which allow remote authentication as possible. The author considers following items as some of the key features of this application: * Thread-based parallel testing. Brute-force testing can be performed against multiple hosts, users or passwords concurrently. * Flexible user input. Target information (host/user/password) can be specified in a variety of ways. For example, each item can be either a single entry or a file containing multiple entries. Additionally, a combination file format allows the user to refine their target listing. * Modular design. Each service module exists as an independent .mod file. This means that no modifications are necessary to the core application in order to extend the supported list of services for brute-forcing.


* ## [**NCRACK**](https://www.kali.org/tools/ncrack/)
  Ncrack is a high-speed network authentication cracking tool. It was built to help companies secure their networks by proactively testing all their hosts and networking devices for poor passwords. Security professionals also rely on Ncrack when auditing their clients. Ncrack was designed using a modular approach, a command-line syntax similar to Nmap and a dynamic engine that can adapt its behaviour based on network feedback. It allows for rapid, yet reliable large-scale auditing of multiple hosts.


* ## [**OPHCRACK**](https://www.kali.org/tools/ophcrack/)
  Ophcrack is a Windows password cracker based on a time-memory trade-off using rainbow tables. This is a new variant of Hellman’s original trade-off, with better performance. It recovers 99.9% of alphanumeric passwords in seconds.


* ## [**WORDLISTS**](https://www.geeksforgeeks.org/create-custom-wordlists-using-crunch-in-kali-linux/)
  This collection of different combinations of characters is called a wordlist. And in order to crack a password or a hash, we need to have a good wordlist that could break the password. So to do so, we have a tool in kali Linux called crunch.


## Wireless Attacks


* ## [**AIRCRACK-NG**](https://www.geeksforgeeks.org/kali-linux-aircrack-ng/)
  Aircrack-ng is a tool that comes pre-installed in Kali Linux and is used for wifi network security and hacking. Aircrack is an all in one packet sniffer, WEP and WPA/WPA2 cracker, analyzing tool and a hash capturing tool. It is a tool used for wifi hacking. It helps in capturing the package and reading the hashes out of them and even cracking those hashes by various attacks like dictionary attacks. It supports almost all the latest wireless interfaces. 
It mainly focuses on 4 areas:
  * Monitoring: Captures cap, packet, or hash files.
  * Attacking: Performs deauthentication or creates fake access points
  * Testing: Checking the wifi cards or driver capabilities
  * Cracking: Various security standards like WEP or WPA PSK.



* ## [**FERN WIFI CRACKER (ROOT)**](https://www.kali.org/tools/fern-wifi-cracker/)
  This package contains a Wireless security auditing and attack software program written using the Python Programming Language and the Python Qt GUI library, the program is able to crack and recover WEP/WPA/WPS keys and also run other network based attacks on wireless or ethernet based networks.


* ## [**KISMET**](https://www.kali.org/tools/kismet/)
  Kismet is a wireless network and device detector, sniffer, wardriving tool, and WIDS (wireless intrusion detection) framework. Kismet works with Wi-Fi interfaces, Bluetooth interfaces, some SDR (software defined radio) hardware like the RTLSDR, and other specialized capture hardware.


* ## [**PIXIEWPS**](https://www.kali.org/tools/pixiewps/)
  Pixiewps is a tool written in C used to bruteforce offline the WPS pin exploiting the low or non-existing entropy of some APs (pixie dust attack). It is meant for educational purposes only.


* ## [**REAVER**](https://www.kali.org/tools/reaver/)
  Reaver performs a brute force attack against an access point’s Wi-Fi Protected Setup pin number. Once the WPS pin is found, the WPA PSK can be recovered and alternately the AP’s wireless settings can be reconfigured. This package also provides the Wash executable, an utility for identifying WPS enabled access points. See documentation in /usr/share/doc/reaver/README.WASH.



* ## [**WIFITE**](https://www.kali.org/tools/wifite/)
  Wifite is a tool to audit WEP or WPA encrypted wireless networks. It uses aircrack-ng, pyrit, reaver, tshark tools to perform the audit.


## Reverse Engineering


* ## [**NASM SHELL**](https://www.kali.org/tools/nasm/)
  Netwide Assembler. NASM will currently output flat-form binary files, a.out, COFF and ELF Unix object files, and Microsoft 16-bit DOS and Win32 object files.
  Also included is NDISASM, a prototype x86 binary-file disassembler which uses the same instruction table as NASM.
  NASM is released under the GNU Lesser General Public License (LGPL).


* ## [**CLANG**](https://www.kali.org/tools/llvm-defaults/)
  Clang project is a C, C++, Objective C and Objective C++ front-end for the LLVM compiler. Its goal is to offer a replacement to the GNU Compiler Collection (GCC).



* ## [**CLANG++**](https://www.kali.org/tools/llvm-defaults/)
   Clang project is a C, C++, Objective C and Objective C++ front-end for the LLVM compiler. Its goal is to offer a replacement to the GNU Compiler Collection (GCC).

* ## [**RADARE2**](https://www.kali.org/tools/radare2/)
  It is composed by an hexadecimal editor (radare) with a wrapped IO layer supporting multiple backends for local/remote files, debugger (OS X, BSD, Linux, W32), stream analyzer, assembler/disassembler (rasm) for x86, ARM, PPC, m68k, Java, MSIL, SPARC, code analysis modules and scripting facilities. A bindiffer named radiff, base converter (rax), shellcode development helper (rasc), a binary information extractor supporting PE, mach0, ELF, class, etc. named rabin, and a block-based hash utility called rahash.


## Exploitation Tools


* ## [**CRACKMAPEXEC**](https://www.kali.org/tools/crackmapexec/)
  This package is a swiss army knife for pentesting Windows/Active Directory environments.
  From enumerating logged on users and spidering SMB shares to executing psexec style attacks, auto-injecting Mimikatz/Shellcode/DLL’s into memory using Powershell, dumping the NTDS.dit and more.
  The biggest improvements over the above tools are:
    * Pure Python script, no external tools required
    * Fully concurrent threading
    * Uses ONLY native WinAPI calls for discovering sessions, users, dumping SAM hashes etc…
    * Opsec safe (no binaries are uploaded to dump clear-text credentials, inject shellcode etc…


* ## [**METASPLOIT FRAMEWORK**](https://www.kali.org/tools/metasploit-framework/)
  One of the best sources of information on using the Metasploit Framework is Metasploit Unleashed, a free online course created by OffSec. Metasploit Unleashed guides you from the absolute basics of Metasploit all the way through to advanced topics.



* ## [**MSF PAYLOAD CREATOR**](https://www.kali.org/tools/msfpc/)
  A quick way to generate various “basic” Meterpreter payloads using msfvenom which is part of the Metasploit framework.


* ## [**SEARCHSPLOIT**](https://www.kali.org/tools/exploitdb/)
  Searchable archive from The Exploit Database. (https://www.exploit-db.com/)


* ## [**SOCIAL ENGINEERING TOOLKIT (ROOT)**](https://www.kali.org/tools/set/)
  The Social-Engineer Toolkit (SET) is an open-source Python-driven tool aimed at penetration testing around Social-Engineering.


* ## [**SQLMAP**](https://www.kali.org/tools/sqlmap/)
  sqlmap goal is to detect and take advantage of SQL injection vulnerabilities in web applications. Once it detects one or more SQL injections on the target host, the user can choose among a variety of options to perform an extensive back-end database management system fingerprint, retrieve DBMS session user and database, enumerate users, password hashes, privileges, databases, dump entire or user’s specific DBMS tables/columns, run his own SQL statement, read specific files on the file system and more.


## Sniffing & Spoofing


* ## [**ETTERCAP-GRAPHICAL**](https://www.kali.org/tools/ettercap/)
  Ettercap supports active and passive dissection of many protocols (even encrypted ones) and includes many feature for network and host analysis.


* ## [**MACCHANGER**](https://www.kali.org/tools/macchanger/)
  GNU MAC Changer is an utility that makes the maniputation of MAC addresses of network interfaces easier. MAC addresses are unique identifiers on networks, they only need to be unique, they can be changed on most network hardware. MAC addresses have started to be abused by unscrupulous marketing firms, government agencies, and others to provide an easy way to track a computer across multiple networks. By changing the MAC address regularly, this kind of tracking can be thwarted, or at least made a lot more difficult.


* ## [**MINICOM**](https://www.kali.org/tools/minicom/)
  Minicom is a clone of the MS-DOS “Telix” communication program. It emulates ANSI and VT102 terminals, has a dialing directory and auto zmodem download.


* ## [**MITMPROXY**](https://www.kali.org/tools/mitmproxy/)
  mitmproxy is an interactive man-in-the-middle proxy for HTTP and HTTPS. It provides a console interface that allows traffic flows to be inspected and edited on the fly.


* ## [**NETSNIFF-NG**](https://www.kali.org/tools/netsniff-ng/)
  netsniff-ng is a high performance Linux network sniffer for packet inspection. It can be used for protocol analysis, reverse engineering or network debugging. The gain of performance is reached by ‘zero-copy’ mechanisms, so that the kernel does not need to copy packets from kernelspace to userspace.


* ## [**RESPONDER**](https://www.kali.org/tools/responder/)
  This package contains Responder/MultiRelay, an LLMNR, NBT-NS and MDNS poisoner. It will answer to specific NBT-NS (NetBIOS Name Service) queries based on their name suffix (see: http://support.microsoft.com/kb/163409). By default, the tool will only answer to File Server Service request, which is for SMB.


* ## [**SCAPY**](https://www.kali.org/tools/scapy/)
  Scapy is a powerful interactive packet manipulation tool, packet generator, network scanner, network discovery, packet sniffer, etc. It can for the moment replace hping, 85% of nmap, arpspoof, arp-sk, arping, tcpdump, tethereal, p0f.


* ## [**TCPDUMP**](https://www.kali.org/tools/tcpdump/)
  This program allows you to dump the traffic on a network. tcpdump is able to examine IPv4, ICMPv4, IPv6, ICMPv6, UDP, TCP, SNMP, AFS BGP, RIP, PIM, DVMRP, IGMP, SMB, OSPF, NFS and many other packet types.


* ## [**WIRESHARK**](https://www.kali.org/tools/wireshark/)
  Wireshark is a network “sniffer” - a tool that captures and analyzes packets off the wire.


## Post Exploitation


* ## [**EVIL-WINRM**](https://www.kali.org/tools/evil-winrm/)
  WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating Systems in order to make life easier to system administrators.


* ## [**EXE2HEX**](https://www.kali.org/tools/exe2hexbat/)
  A Python script to convert a Windows PE executable file to a batch file and vice versa.


* ## [**IMPACKET**](https://www.kali.org/tools/impacket/)
  Impacket is a collection of Python3 classes focused on providing access to network packets. Impacket allows Python3 developers to craft and decode network packets in simple and consistent manner. It includes support for low-level protocols such as IP, UDP and TCP, as well as higher-level protocols such as NMB and SMB.


* ## [**MIMIKATZ**](https://www.kali.org/tools/mimikatz/)
  Mimikatz uses admin rights on Windows to display passwords of currently logged in users in plaintext.


* ## [**NETCAT**](https://www.kali.org/tools/netcat/)
  A simple Unix utility which reads and writes data across network connections using TCP or UDP protocol. It is designed to be a reliable “back-end” tool that can be used directly or easily driven by other programs and scripts. At the same time it is a feature-rich network debugging and exploration tool, since it can create almost any kind of connection you would need and has several interesting built-in capabilities.


* ## [**POWERSHELL EMPIRE**](https://www.kali.org/tools/powershell-empire/)
  This package contains a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python Linux/OS X agent. It is the merge of the previous PowerShell Empire and Python EmPyre projects. The framework offers cryptologically-secure communications and a flexible architecture. On the PowerShell side, Empire implements the ability to run PowerShell agents without needing powershell.exe, rapidly deployable post-exploitation modules ranging from key loggers to Mimikatz, and adaptable communications to evade network detection, all wrapped up in a usability-focused framework.


* ## [**POWERSPLOIT**](https://www.kali.org/tools/powersploit/)
  PowerSploit is a series of Microsoft PowerShell scripts that can be used in post-exploitation scenarios during authorized penetration tests.


* ## [**PROXYCHAINS4**](https://dranolia.medium.com/understanding-proxychains4-conf-anonsurf-in-kali-linux-46471260e499)
  Proxychains is a powerful tool that enables users to run any application through a proxy server. It is particularly useful for maintaining anonymity and bypassing network restrictions. In Kali Linux, a popular penetration testing distribution, Proxychains is commonly used for concealing the identity of the user during security assessments.


* ## [**STARKILLER**](https://www.kali.org/tools/starkiller/)
  This package contains a Frontend for Powershell Empire. It is an Electron application written in VueJS.


* ## [**WEEVELY**](https://www.kali.org/tools/weevely/)
  Weevely is a stealth PHP web shell that simulate telnet-like connection. It is an essential tool for web application post exploitation, and can be used as stealth backdoor or as a web shell to manage legit web accounts, even free hosted ones.


## Forensics


* ## [**AIUTOPSY (ROOT)**](https://www.kali.org/tools/autopsy/)
  The Autopsy Forensic Browser is a graphical interface to the command line digital forensic analysis tools in The Sleuth Kit. Together, The Sleuth Kit and Autopsy provide many of the same features as commercial digital forensics tools for the analysis of Windows and UNIX file systems (NTFS, FAT, FFS, EXT2FS, and EXT3FS).


* ## [**BINWALK**](https://www.kali.org/tools/binwalk/)
  Binwalk is a tool for searching a given binary image for embedded files and executable code. Specifically, it is designed for identifying files and code embedded inside of firmware images. Binwalk uses the libmagic library, so it is compatible with magic signatures created for the Unix file utility.


* ## [**BULK_EXTRACTOR**](https://www.kali.org/tools/bulk-extractor/)
  bulk_extractor is a C++ program that scans a disk image, a file, or a directory of files and extracts useful information without parsing the file system or file system structures. The results are stored in feature files that can be easily inspected, parsed, or processed with automated tools. bulk_extractor also creates histograms of features that it finds, as features that are more common tend to be more important.


* ## [**HASHDEEP**](https://www.kali.org/tools/hashdeep/)
  hashdeep is a set of tools to compute MD5, SHA1, SHA256, tiger and whirlpool hashsums of arbitrary number of files recursively.


## Repairing ToolS


* ## [**CHERRYTREE**]()




















