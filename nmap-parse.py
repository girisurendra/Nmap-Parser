from libnmap.parser import NmapParser
import netaddr
import re
import argparse
import csv
import os


def filters(hosts, ips_up, service, tcp_ports, udp_ports, port_state, print_type, export_type, file=None):
    zero_ports = len(ips_up)
    for ip_address in ips_up:
        tcp_port_nmap, udp_port_nmap = full_port_list_per_IP(hosts, ip_address, port_state)
        len_tcp = len(tcp_port_nmap)
        len_udp = len(udp_port_nmap)
        if len_tcp > 0:
            if service is not None:
                filter_by_service(ip_address, service, tcp_port_nmap, print_type, export_type, file)
            elif tcp_ports is not None:
                filter_by_per_port(ip_address, tcp_ports, tcp_port_nmap, print_type, export_type, file)
            elif udp_ports is not None:
                print(
                    "Unfortunately the NMAP file only contains TCP ports and you've specified -u flag to filter by UDP ports")
                exit()
            else:
                filter_by_IP(ip_address, tcp_port_nmap, print_type, export_type, file)
        elif len_udp > 0:
            if service is not None:
                filter_by_service(ip_address, service, udp_port_nmap, print_type, export_type, file)
            elif udp_ports is not None:
                filter_by_per_port(ip_address, udp_ports, udp_port_nmap, print_type, export_type, file)
            elif tcp_ports is not None:
                print(
                    "Unfortunately the NMAP file only contains UDP ports and you've specified -t flag to filter by TCP ports")
                exit()
            else:
                filter_by_IP(ip_address, udp_port_nmap, print_type, export_type, file)
        else:
            zero_ports -= 1

    if zero_ports == 0:
        print(
            "The given Nmap file has no ports with specified state (default is open). May be try a different -ps switch?")


def full_port_list(host, protocol, port_state):
    """:returns tcp_ports & UDP_ports"""
    ports = []
    no_ports = len(host.get_ports())
    for port, proto in host.get_ports():
        if proto == protocol:
            if no_ports > 40000:
                print(
                    "The IP address {} has {} no.of ports open, therefore isn't filtered. Considering using --exculde-ip flag to exclude the IP.".format(
                        host.address, no_ports))
                break
            else:
                nmapservice = host.get_service(port, proto)
                if nmapservice.state == port_state:
                    state = nmapservice.state
                    serviceName = nmapservice.service
                    banner = nmapservice.banner
                    script_results = nmapservice.scripts_results
                    ports.append((port, proto, state, serviceName, banner, script_results))
        else:
            break

    return ports


def full_port_list_per_IP(host, ips, port_state):
    for host in host:
        if ips == host.address:
            ''' Need Error Handling Here (Not required, only live IPs are fed'''
            tcp_ports_per_IP = full_port_list(host, "tcp", port_state)
            udp_port_per_IP = full_port_list(host, "udp", port_state)
    return tcp_ports_per_IP, udp_port_per_IP


def filter_by_service(ip_address, service, port_nmap, print_type, export_type, file):
    services_matched = []
    for services in service:
        for each_service in port_nmap:
            service_match = re.compile(services)
            if service_match.search(each_service[3]):
                services_matched.append(each_service)
    if print_type == "nmap":
        print_as_in_nmap(ip_address, services_matched, export_type, file)
    elif print_type == "list":
        print_in_list('list_service', ip_address, services_matched, export_type, file)
    else:
        print_in_list('list_ip', ip_address, services_matched, export_type, file)


def filter_by_IP(ip_address, ports_nmap, print_type, export_type, file):
    if print_type == 'nmap':
        print_as_in_nmap(ip_address, ports_nmap, export_type, file)
    elif print_type == 'list':
        print_in_list('list_port', ip_address, ports_nmap, export_type, file)
    else:
        print_in_list('list_ip', ip_address, ports_nmap, export_type, file)


def filter_by_per_port(ip_address, ports, port_nmap, print_type, export_type, file):
    if ports is not None:
        ports_matched = []
        for port in ports:
            for each_port in port_nmap:
                if each_port[0] == int(port):
                    ports_matched.append(each_port)
                    break
        if len(ports_matched):
            if print_type == "nmap":
                print_as_in_nmap(ip_address, ports_matched, export_type, file)
            elif print_type == "list":
                print_in_list('list_port', ip_address, ports_matched, export_type, file)
            else:
                print_in_list('list_ip', ip_address, ports_matched, export_type, file)


def print_default(live_ip, dead_ip, hosts_up, hosts_down, verbose):
    if verbose:
        total_ips = len(live_ip) + len(dead_ip)
        print("Total no.of IP addresses: {}".format(total_ips))
        print("Total no.of IP address with status up: {}".format(len(live_ip)))
        print("\n")
        print("IPs(with status up)\tStatus\tNo.of Open ports(status=open)\thostname")
        for hosts in hosts_up:
            n_ports = len(hosts.get_open_ports())
            status = hosts.status
            hostname = hosts.hostnames
            if len(hostname):
                hostname = hostname[0]
            else:
                hostname = '-'
            print("{}{}{}{}{}{}{}".format(hosts.address, ((24 - len(hosts.address)) * ' '), status,
                                          ((8 - len(status)) * ' '), n_ports, ((32 - len(str(n_ports))) * ' '),
                                          hostname))
        if len(hosts_down) > 0:
            print("IPs(with other status)\tStatus\t\thostname")
            for hostsd in hosts_down:
                status = hostsd.status
                hostname = hostsd.hostnames
                if len(hostname):
                    hostname = hostname[0]
                else:
                    hostname = '-'
                if len(hostname) > 0:
                    print("{}{}{}{}{}".format(hostsd.address, ((24 - len(hostsd.address)) * ' '), status,
                                              ((16 - len(status)) * ' '), hostname))
    else:
        for lives_ip in live_ip:
            print(lives_ip)


def print_as_in_nmap(ip_address, ports_nmap, export_type, file):
    if ports_nmap is not None:
        if export_type is not None:
            export_file(ip_address, ports_nmap, file)
        if len(ports_nmap) > 0:
            print("============")
            print("IP address:{}".format(ip_address))
            '''May be this IF statement isn't required'''
            print("PORT\t\tSTATE\t\tSERVICE\t\tVERSION")
            for ports in ports_nmap:
                port = str(ports[0])
                protocol = ports[1]
                state = ports[2]
                service = ports[3]
                version = ports[4]
                scripts = ports[5]
                port_protocol = [port, protocol]
                ''' Removing duplicate items'''
                pp = '/'.join(port_protocol)
                sp = ' '
                nsp = ''
                pattern = 'product:|extrainfo:|ostype:|Linux$|Windows$'
                version = re.sub(pattern, nsp, version) if len(version) > 0 else "-"
                print(
                    "{0}{1}{2}{3}{4}{5}{6}".format(pp, ((16 - len(pp)) * sp), state, ((16 - len(state)) * sp), service,
                                                   ((16 - len(service)) * sp), version))
                if len(scripts) > 0:
                    # print("|")
                    # print(scripts)
                    for items in range(0, len(scripts)):
                        # del scripts[items]['elements']
                        id = scripts[items]['id']
                        output = scripts[items]['output']
                        output = re.sub('\n', '\n |_', output) if '\n' in output else output
                        print("|_{}:{}".format(id, output))


def print_in_list(print_by, ip_address, ports_matched, export_type, file):
    if export_type is not None:
        export_file(ip_address, ports_matched, file)
    """ Print IP:Port, Port"""
    if print_by == 'list_port':
        if ports_matched is not None:
            if len(ports_matched) > 0:
                ports = []
                for port in ports_matched:
                    ports.append(str(port[0]))
                print("{}: {}".format(ip_address, ','.join(ports)))

    """ Print IP:Port (Service), Port(Service)"""
    if print_by == 'list_service':
        if ports_matched is not None:
            if len(ports_matched) > 0:
                ports_services = []
                for port_service in ports_matched:
                    port = str(port_service[0])
                    service = port_service[3]
                    portService = port + '(' + service + ')'
                    ports_services.append(portService)
                print("{}: {}".format(ip_address, ', '.join(ports_services)))

    """ Print IP"""
    if print_by == 'list_ip':
        if ports_matched is not None:
            print(ip_address)


def export_file(ip_address, ports_matched, file):
    if ports_matched is not None:
        if len(ports_matched) > 0:
            export_detail = []
            for each_ports in ports_matched:
                service_detail = [ip_address, str(each_ports[0]), str(each_ports[1]), str(each_ports[2]),
                                  str(each_ports[3])]
                version = str(each_ports[4])
                pattern = 'product:|extrainfo:|ostype:|Linux$|Windows$'
                nsp = ''
                version = re.sub(pattern, nsp, version) if len(version) > 0 else "-"
                service_detail.append(version)
                export_detail.append(service_detail)
            writer = csv.writer(file)
            writer.writerows(export_detail)


def parse_service(toParse_service=None):
    parsed_services = []
    if re.search(',', toParse_service) is None:
        parsed_services.append(toParse_service.lower())
    for toParseService in toParse_service.split(','):
        parsed_services.append(toParseService.lower())
    parsed_services = list(dict.fromkeys(parsed_services))
    return parsed_services


def parse_ip(toParse_ip=None):
    parsed_ip = []
    if re.search('[-,/]', toParse_ip) is None:
        parsed_ip.append(toParse_ip)
        return parsed_ip
    for toParseIPC in toParse_ip.split(','):
        if '/' in toParseIPC:
            for toParseIPS in IPNetwork(toParseIPC):
                parsed_ip.append(str(toParseIPS))
        else:
            parsed_ip.append(toParseIPC)
    "remove duplicate entries"
    parsed_ip = list(dict.fromkeys(parsed_ip))
    return parsed_ip


def parse_port(toParse_Port=None):
    parsed_port = []
    if re.search('[-,]', toParse_Port) is None:
        parsed_port.append(toParse_Port)
        return parsed_port
    for toParse_PortC in toParse_Port.split(','):
        if '-' in toParse_PortC:
            port_range = toParse_PortC.split('-')
            for i in range(int(port_range[0]), int(port_range[1]) + 1):
                parsed_port.append(str(i))
        else:
            parsed_port.append(toParse_PortC)
    '''remove duplicate entries'''
    parsed_port = list(dict.fromkeys(parsed_port))
    return parsed_port


def get_up_down_hosts(a_hosts):
    """ :returns NmapHosts objects and IP addresses which are up and down"""
    up_hosts = []
    down_hosts = []
    alive_ip = []
    dead_ip = []
    for live_hosts in a_hosts:
        if live_hosts.is_up():
            up_hosts.append(live_hosts)
            alive_ip.append(live_hosts.address)
        else:
            down_hosts.append(live_hosts)
            dead_ip.append(live_hosts.address)
    return up_hosts, down_hosts, alive_ip, dead_ip


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="A tool that attempts to parse nmap XML output!!")
    parser.add_argument("file", nargs=1, help="Nmap XML output")
    parser.add_argument("-i", "--ip",
                        help="specify a specific IP address or multiple IP addresses separated by comma or a subnet")
    parser.add_argument("-ei", "--exclude-ip",
                        help="specify a specific IP address or multiple IP addresses separated by comma or a subnet")
    parser.add_argument("-t", "--tcp",
                        help="specify the filter to parse/search TCP ports only. Comma separation/port ranges allowed")
    parser.add_argument("-u", "--udp",
                        help="specify the filter to parse/search UDP ports only. Comma separation/port ranges allowed")
    parser.add_argument("-s", "--service", help="specify the service name to filter by.")
    parser.add_argument("--nmap", action='store_true',
                        help="print the output as in Nmap format. This is the default mode")
    parser.add_argument("--list", action='store_true', help="print the output in list format; easy for copy/paste")
    parser.add_argument("-ps", "--status",
                        help="specify the state of the port. Options are open, closed, filtered, unfiltered, \"open|filtered\", \"closed|filtered\"; by default only ports with open state are filtered ")
    parser.add_argument("--export",
                        help="export the filtered output to a csv file.")
    parser.add_argument("-v", "--verbose", action='store_true', help="Give more detailed information!!")

    args = parser.parse_args()
    nmap_report = NmapParser.parse_fromfile(args.file[0])

    '''Fetch All Hosts from the Nmap File'''
    hosts = nmap_report.hosts

    '''Fetch NmapHost object with Status up and status down. Need to print the alive hosts too??'''
    hosts_up, hosts_down, live_ip, dead_ip = get_up_down_hosts(hosts)

    '''Parsing IPs; Get alive IPs if IP addresses not specified'''
    if not args.ip and not args.service and not args.tcp and not args.udp and not args.status and not args.nmap and not args.list and not args.export:
        print_default(live_ip, dead_ip, hosts_up, hosts_down, args.verbose)
        exit()

    ips_up = []
    ips_excluded = []
    if args.exclude_ip:
        excluded_ip = parse_ip(args.exclude_ip)
        for excluded_ip in excluded_ip:
            for exclude_ip in live_ip:
                if exclude_ip == excluded_ip:
                    ips_excluded.append(exclude_ip)
        if len(ips_excluded) == 0:
            print("The IPs you've excluded do not have status up in the Nmap file you've provided")
            exit()

    if args.ip:
        parsed_ip = parse_ip(args.ip)
        for parsed_ip in parsed_ip:
            for lives_ip in live_ip:
                if lives_ip == parsed_ip:
                    ips_up.append(lives_ip)
        ips_up = list(set(ips_up).difference(ips_excluded))
        if len(ips_up) == 0:
            print("You've entered \"Dead IP\"")
            exit()
    else:
        for host_up in hosts_up:
            ips_up.append(host_up.address)
        ips_up = list(set(ips_up).difference(ips_excluded))

    '''Parsing services'''
    parsed_services = parse_service(args.service) if args.service else None

    ''''Parsing Ports'''
    tcp_ports = parse_port(args.tcp) if args.tcp else None
    udp_ports = parse_port(args.udp) if args.udp else None

    '''Parsing port state (Only one supported at the moment'''
    if args.status:
        ps = args.status.lower()
        ps_options = ['open', 'filtered', 'open|filtered', 'unfiltered', 'closed', 'closed|filtered']
        port_state = ps if ps in ps_options else 'The provided port state is invalid'
    else:
        port_state = 'open'

    '''Parsing the type of filter output'''
    if args.nmap:
        print_type = "nmap"
    elif args.list:
        print_type = "list"
    else:
        print_type = None

    '''Checking if export is required or not'''
    if args.export:
        export_type = args.export if "csv" in args.export else args.export + ".csv"
        if os.path.isfile(args.export) or os.path.isfile(export_type):
            print("The file you've specified already exists in the current working directory!!")
            exit()
        csv_title = ["IP", "PORT", "PROTOCOL", "STATUS", "SERVICE", "VERSION"]
        with open(export_type, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(csv_title)
            filters(hosts_up, ips_up, parsed_services, tcp_ports, udp_ports, port_state, print_type, export_type, file)
    else:
        export_type = None
        filters(hosts_up, ips_up, parsed_services, tcp_ports, udp_ports, port_state, print_type, export_type)
