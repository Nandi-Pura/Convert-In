import type {Entity,Result} from './types';
const source = [
'config firewall address',
'    edit "WEB_SERVER"',
'        set subnet 10.10.10.10 255.255.255.255',
'        set comment "Web Server"',
'    next',
'',
'    edit "APP_SERVERS"',
'        set subnet 10.10.20.0 255.255.255.0',
'        set comment "Application Servers"',
'    next',
'',
'    edit "DB_SERVERS"',
'        set subnet 10.10.30.0 255.255.255.0',
'        set comment "Database Servers"',
'    next',
'',
'    edit "SSLVPN_TUNNEL_ADDR1"',
'        set type iprange',
'        set start-ip 192.168.1.10',
'        set end-ip 192.168.1.50',
'        set comment "SSL VPN Tunnel Range"',
'    next',
'end',
].join('\n');
const commands=[
['set address WEB_SERVER ip-netmask 10.10.10.10/32','set address WEB_SERVER description "Web Server"'],
['set address-group APP_SERVERS static','set address-group APP_SERVERS description "Application Servers"','set address-group APP_SERVERS member 10.10.20.0/24'],
];
export const referenceEntities:Entity[]=[
{id:'web',entity_type:'Address',source_title:'WEB_SERVER',source_snippet:'',source_lines:[2,3,4,5],target_snippet:commands[0].join('\n'),user_status:'READY',detailed_status:'EXACT',copyable:true,commands:commands[0],findings:['Exact address and subnet successfully migrated.']},
{id:'app',entity_type:'Address Group',source_title:'APP_SERVERS',source_snippet:'',source_lines:[7,8,9,10],target_snippet:commands[1].join('\n'),user_status:'READY',detailed_status:'SUPPORTED',copyable:true,commands:commands[1],findings:['Syntax and structure changed to match PAN-OS address group format.']},
{id:'db',entity_type:'Address Group',source_title:'DB_SERVERS',source_snippet:'',source_lines:[12,13,14,15],target_snippet:'',user_status:'REVIEW REQUIRED',detailed_status:'MANUAL_REVIEW',copyable:false,commands:[],findings:['Verify member definition and usage in security policies.']},
{id:'vpn',entity_type:'Address',source_title:'SSLVPN_TUNNEL_ADDR1',source_snippet:'',source_lines:[17,18,19,20,21,22],target_snippet:'',user_status:'BLOCKED',detailed_status:'UNSUPPORTED',copyable:false,commands:[],findings:['IP range needs manual configuration with zone mapping.']},
];
export const referenceResult:Result={
project_id:'visual-fixture',mode:'CONVERT',renderer_available:true,
source_profile:{id:'fixture-source',vendor:'Fortinet',platform:'FortiGate',domain:'FIREWALL',supported_versions:[],target_capability:'',version:'7.0.13',os_family:'FortiOS'},
target_profile:{id:'fixture-target',vendor:'Palo Alto Networks',platform:'PAN-OS',domain:'FIREWALL',supported_versions:[],target_capability:'',version:'11.1',os_family:'PAN-OS'},
source_text:source,candidate:[...commands[0],'',...commands[1],'','','# DB_SERVERS requires engineer review.','','','# No direct equivalent - requires manual configuration','# SSL VPN tunnel address range needs zone mapping','# review'].join('\n'),
cp0_summary:{},cp1_summary:{},cp2_summary:null,entities:referenceEntities,lint_findings:[],
line_accounting:{total_analyzed_lines:41820,converted_lines:26066,review_lines:11548,unsupported_lines:2430,unchanged_lines:1776,method:'Reference image visual fixture; not a conversion result'},
};
