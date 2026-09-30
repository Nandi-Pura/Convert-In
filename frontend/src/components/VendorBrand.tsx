import {Icon} from './Icon';

type VendorDefinition={
  id:string;
  label:string;
  aliases:string[];
  asset?:string;
  alt?:string;
  maxWidth?:number;
  maxHeight?:number;
  opticalScale?:number;
  translateX?:number;
  translateY?:number;
};

const vendors:VendorDefinition[]=[
  {id:'palo-alto',label:'Palo Alto Networks',aliases:['palo alto','palo alto networks','palo_alto','pan-os','pan os']},
  {id:'fortinet',label:'Fortinet',aliases:['fortinet','fortigate','forti os','fortios']},
  {id:'cisco',label:'Cisco',aliases:['cisco','ios','ios xe','iosxe']},
  {id:'check-point',label:'Check Point',aliases:['check point','check_point','checkpoint']},
  {id:'juniper',label:'Juniper Networks',aliases:['juniper','juniper networks','junos']},
  {id:'hpe-aruba',label:'HPE Aruba Networking',aliases:['hpe aruba','hpe_aruba','aruba','aruba networking']},
  {id:'f5',label:'F5',aliases:['f5','f5 networks','big-ip','big ip']},
];

const normalize=(value:string)=>value.trim().toLowerCase().replace(/[-_]+/g,' ').replace(/\s+/g,' ');
const titleCase=(value:string)=>value.toLowerCase().replace(/\b\w/g,letter=>letter.toUpperCase());

export function vendorDefinition(value:string){
  const normalized=normalize(value);
  return vendors.find(vendor=>vendor.aliases.some(alias=>normalize(alias)===normalized));
}

export function vendorDisplayName(value:string){
  if(!value)return 'Vendor';
  return vendorDefinition(value)?.label||titleCase(value.replaceAll('_',' ').replaceAll('-',' '));
}

export function VendorBrand({vendor,compact=false}:{vendor:string;compact?:boolean}){
  const definition=vendorDefinition(vendor),label=definition?.label||vendorDisplayName(vendor);
  const accessibleLabel=definition?.alt||label;
  const bounded=(value:number|undefined,min:number,max:number,fallback:number)=>Math.min(max,Math.max(min,value??fallback));
  const style={
    '--vendor-max-width':`${bounded(definition?.maxWidth,120,148,148)}px`,
    '--vendor-max-height':`${bounded(definition?.maxHeight,28,40,36)}px`,
    '--vendor-optical-scale':String(bounded(definition?.opticalScale,.9,1.1,1)),
    '--vendor-translate-x':`${bounded(definition?.translateX,-3,3,0)}px`,
    '--vendor-translate-y':`${bounded(definition?.translateY,-3,3,0)}px`,
  } as React.CSSProperties;
  return <span className={`vendor-brand${compact?' compact':''}`} role="img" aria-label={accessibleLabel} style={style}>
    {definition?.asset?<img src={definition.asset} alt="" aria-hidden="true"/>:<span className="vendor-brand-fallback"><Icon name="vendor"/><b>{label}</b></span>}
  </span>;
}
