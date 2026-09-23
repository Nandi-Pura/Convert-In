"""Development-only synthetic fixtures. Never imported by application runtime."""
from dataclasses import dataclass

@dataclass(frozen=True)
class Tier:
    objects:int; services:int; policies:int

TIERS={"small":Tier(20,10,10),"medium":Tier(250,100,250),"large":Tier(1000,500,1000)}

def asa(tier:str)->str:
    n=TIERS[tier]; lines=["! synthetic = true; vendor = Cisco ASA; version = 9.20; coverage = realistic regression", "ASA Version 9.20", "interface GigabitEthernet0/0", " nameif outside", " security-level 0", " ip address 192.168.255.2 255.255.255.0", "!", "interface GigabitEthernet0/1", " nameif inside", " security-level 100", " ip address 10.255.0.1 255.255.255.0", "!"]
    for i in range(n.objects): lines += [f"object network APP_{i:04}", f" host 10.{i//65536}.{(i//256)%256}.{i%256}"]
    lines += ["object network Range_Object", " range 10.200.0.1 10.200.0.20", "object-group network NESTED_INNER", " network-object object APP_0000", "object-group network NESTED_OUTER", " group-object NESTED_INNER", " group-object UNKNOWN_GROUP", "object network unused.object", " host 10.254.254.254", "object network Collision_Name", " host 10.254.0.1", "object network collision_name", " host 10.254.0.2"]
    for i in range(n.services): lines += [f"object service TCP_{i:04}", f" service tcp destination eq {10000+i}"]
    lines += ["object-group service WEB_GROUP tcp", " service-object object TCP_0000", "access-list EDGE remark synthetic ordered policy set"]
    for i in range(n.policies): lines.append(f"access-list EDGE line {i+1} extended permit tcp any object APP_{i%n.objects:04} object TCP_{i%n.services:04}")
    lines += ["access-list EDGE line 9999 extended deny ip any any inactive", "access-list EDGE line 10000 extended permit ip object MISSING_OBJECT any", "access-group EDGE in interface inside", "route outside 10.240.0.0 255.255.0.0 192.168.255.1 10", "nat (inside,outside) source static APP_0000 APP_0001", "unknown synthetic command"]
    return "\n".join(lines)+"\n"

def fortigate(tier:str)->str:
    n=TIERS[tier]; out=["# synthetic = true; vendor = FortiGate; version = 7.4; coverage = realistic regression", "#config-version=FGT60F-7.4.0-FW-build0000-000000:opmode=0:vdom=0:user=synthetic", "config system interface", ' edit "wan1"', "  set ip 192.168.255.2 255.255.255.0", " next", ' edit "lan"', "  set ip 10.255.0.1 255.255.255.0", " next", ' edit "vlan100"', '  set interface "lan"', "  set vlanid 100", "  set ip 10.100.0.1 255.255.255.0", " next", "end", "config system zone", ' edit "TRUST"', '  set interface "lan" "vlan100"', " next", "end", "config firewall address"]
    for i in range(n.objects): out += [f' edit "APP_{i:04}"', f"  set subnet 10.{i//65536}.{(i//256)%256}.{i%256} 255.255.255.255", " next"]
    out += [' edit "unused.object"','  set subnet 10.254.254.254 255.255.255.255',' next',' edit "Collision Name"','  set subnet 10.254.0.1 255.255.255.255',' next',' edit "collision_name"','  set subnet 10.254.0.2 255.255.255.255',' next',"end","config firewall addrgrp",' edit "NESTED_INNER"','  set member "APP_0000"',' next',' edit "NESTED_OUTER"','  set member "NESTED_INNER" "UNKNOWN_GROUP"',' next',"end","config firewall service custom"]
    for i in range(n.services): out += [f' edit "TCP_{i:04}"',f"  set tcp-portrange {10000+i}"," next"]
    out += ["end","config firewall service group",' edit "WEB_GROUP"','  set member "TCP_0000"'," next","end","config firewall vip",' edit "SYNTHETIC_VIP"','  set extip 192.168.255.10','  set mappedip "APP_0000"','  set extintf "wan1"'," next","end","config firewall policy"]
    for i in range(n.policies): out += [f" edit {i+1}",f'  set name "Ordered Policy {i+1}"','  set srcintf "TRUST"','  set dstintf "wan1"',f'  set srcaddr "APP_{i%n.objects:04}"','  set dstaddr "all"',f'  set service "TCP_{i%n.services:04}"',"  set action accept",f'  set comments "synthetic order {i+1}"',*( ["  set nat enable"] if i==0 else [])," next"]
    out += [" edit 9999",'  set name "Disabled synthetic"','  set srcintf "TRUST"','  set dstintf "wan1"','  set srcaddr "MISSING_OBJECT"','  set dstaddr "all"','  set service "ALL"','  set status disable'," next","end","config router static"," edit 1","  set dst 10.240.0.0 255.255.0.0","  set gateway 192.168.255.1",'  set device "wan1"'," next","end","config system sdwan","end"]
    return "\n".join(out)+"\n"

def juniper_srx(tier:str)->str:
    n=TIERS[tier]; out=["## Last changed: synthetic Junos: 23.4R2","set security zones security-zone trust interfaces ge-0/0/0.0","set security zones security-zone untrust interfaces ge-0/0/1.0"]
    for i in range(n.objects): out.append(f"set security address-book global address APP_{i:04} 10.{i//65536}.{(i//256)%256}.{i%256}/32")
    for i in range(n.services): out += [f"set applications application TCP_{i:04} protocol tcp",f"set applications application TCP_{i:04} destination-port {10000+i}"]
    for i in range(n.policies): out += [f"set security policies from-zone trust to-zone untrust policy P{i:04} match source-address any",f"set security policies from-zone trust to-zone untrust policy P{i:04} match destination-address APP_{i%n.objects:04}",f"set security policies from-zone trust to-zone untrust policy P{i:04} match application TCP_{i%n.services:04}",f"set security policies from-zone trust to-zone untrust policy P{i:04} then permit"]
    out += ["set security nat source rule-set OUT rule PAT then source-nat interface","set security unknown synthetic"]
    return "\n".join(out)+"\n"

def iosxe_router(tier:str)->str:
    n=TIERS[tier]; out=["Cisco IOS XE Software, Version 17.12.1","hostname SYNTHETIC","vrf definition CUSTOMER"]
    for i in range(n.objects): out += [f"interface Loopback{i}",f" ip address 10.{i//65536}.{(i//256)%256}.{i%256} 255.255.255.255"]
    for i in range(n.policies): out.append(f"ip route 172.{i//65536}.{(i//256)%256}.{i%256} 255.255.255.255 192.0.2.1")
    for i in range(n.services): out.append(f"ip prefix-list PL seq {i*5+5} permit 10.0.0.0/8 ge 16 le 24")
    out += ["route-map EDGE permit 10"," match ip address prefix-list PL","router bgp 65000"]
    for i in range(n.objects): out.append(f" neighbor 192.0.{i//256}.{i%256} remote-as {65100+i}")
    return "\n".join(out)+"\n"