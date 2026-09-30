import ipaddress

_LOCAL_ROOTS=("set address ","set address-group ","set service ","set service-group ","set zone ","set network interface ","set network virtual-router ","set rulebase security rules ","set rulebase nat rules ")

def validate_candidate(lines):
    errors=[]
    for number,line in enumerate(lines,1):
        if not line.startswith(_LOCAL_ROOTS): errors.append(f"Line {number}: unrecognized context")
        if " ip-netmask " in line:
            try: ipaddress.ip_network(line.rsplit(" ",1)[1],strict=False)
            except ValueError: errors.append(f"Line {number}: invalid network")
        if " protocol " in line and " port " in line:
            port=line.rsplit(" ",1)[1]
            if not all(x.isdigit() and 0<=int(x)<=65535 for x in port.split("-")): errors.append(f"Line {number}: invalid port")
    return errors