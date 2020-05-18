# Nmap-Parser
Parse xml output of a Nmap scan and export to a CSV file.

## Usage
```
### pip3 install -r requirements.txt
```

```
### python3 nmap-parse.py --help
usage: nmap-parse.py [-h] [-i IP] [-t TCP] [-u UDP] [-s SERVICE] [--nmap]
                     [--list] [-ps STATUS] [--export EXPORT]
                     file

A tool that attempts to parse nmap XML output!!

positional arguments:
  file                  Nmap XML output

optional arguments:
  -h, --help            show this help message and exit
  -i IP, --ip IP        specify a specific IP address or multiple IP addresses
                        separated by comma or a subnet
  -t TCP, --tcp TCP     specify the filter to parse/search TCP ports only.
                        Comma separation/port ranges allowed
  -u UDP, --udp UDP     specify the filter to parse/search UDP ports only.
                        Comma separation/port ranges allowed
  -s SERVICE, --service SERVICE
                        specify the service name to filter by.
  --nmap                print the output as in Nmap format. This is the
                        default mode
  --list                print the output in list format; easy for copy/paste
  -ps STATUS, --status STATUS
                        specify the state of the port. Options are open,
                        closed, filtered, unfiltered, "open|filtered",
                        "closed|filtered"; by default only ports with open
                        state are filtered
  --export EXPORT       export the filtered output to a csv file.
```

## Examples
- List all IPs with status up
    python3 nmap-parse.py <File_Name>
- Display output of a specific IP in nmap format
    python3 nmap-parse.py <File_Name> -i <IP_address> --nmap
- Display IP address with specific ports as a list
    python3 nmap-parse.py <File_Name> - t 53, 22 --list
- Display IP address with specific service as a list
    python3 nmap-parse.py <File_Name> -s http,dns --list
- Display IP addresses with specific port status in nmap format
    python3 nmap-parse.py <File_Name> -ps "open|filtered" -u 53 --nmap
- Export filtered output in CSV format
    python3 nmap-parse.py Full_TCP.xml -t 53 --export port53.csv