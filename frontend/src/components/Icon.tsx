const paths={
  list:'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01',
  download:'M12 3v12m-5-5 5 5 5-5M4 15v6h16v-6',copy:'M8 7V3h12v14h-4M4 7h12v14H4Z',
  expand:'M14 3h7v7m0-7-7 7M10 21H3v-7m0 7 7-7',restore:'M9 4H4v5m0-5 6 6M15 20h5v-5m0 5-6-6',
  search:'m21 21-4.4-4.4m2.4-5.1a7.5 7.5 0 1 1-15 0 7.5 7.5 0 0 1 15 0',filter:'M4 5h16l-6 7v6l-4 2v-8L4 5Z',
  settings:'M9 3h6l1 4 4 2v6l-4 2-1 4H9l-1-4-4-2V9l4-2 1-4Zm3 5a4 4 0 1 0 0 8 4 4 0 0 0 0-8',
  trash:'M3 6h18M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7m4-7v7',
  targetFile:'M3 5h12a6 6 0 0 1 0 12H4m-1-3 3 3-3 3M3 5v5h5',share:'M8 11l8-6M8 13l8 6M5 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6M19 2a3 3 0 1 0 0 6 3 3 0 0 0 0-6M19 16a3 3 0 1 0 0 6 3 3 0 0 0 0-6',
  brand:'',folder:'M3 7V5h6l2 2h10v13H3V7Zm0 3h18',save:'M4 3h13l3 3v15H4V3Zm4 0v6h8V3M8 21v-8h8v8',file:'M5 2h9l5 5v15H5V2Zm9 0v6h5M9 12h6m-6 4h6',
  menu:'M12 4h.01M12 12h.01M12 20h.01',chevron:'m7 10 5 5 5-5',help:'M9 9a3 3 0 1 1 5 2c-2 1-2 2-2 3m0 3h.01',shield:'m12 2 8 4v6c0 5-8 10-8 10S4 17 4 12V6l8-4Zm-3 9 3 3 4-5',
  source:'M12 16V2m-6 6 6-6 6 6M5 11H3v10h18V11h-2',target:'M20 12a8 8 0 1 1-8-8m4 8a4 4 0 1 1-4-4m0 4 9-9m-5 0h5v5',vendor:'m3 15 8-8 3 3-8 8-3-3Zm7 2 8-8 3 3-8 8-3-3ZM7 7l4-4 3 3',hardware:'M3 4h18v6H3V4Zm0 10h18v6H3v-6Zm4-7h.01M7 17h.01M12 7h6m-6 10h6',
  check:'m6 12 4 4 8-8',play:'m8 4 12 8-12 8V4Z',info:'M12 11v6m0-10h.01',chart:'M4 20V11h3v9H4Zm7 0V3h3v17h-3Zm7 0v-6h3v6h-3Z',branch:'M8 3v18m0-14 8 5m0 0-4-4m4 4-4 4M5 3h6M5 21h6',compare:'M3 8h17m-5-5 5 5-5 5M21 16H4m5-5-5 5 5 5',
  arrowRight:'M5 12h14m-6-6 6 6-6 6',plus:'M12 6v12m-6-6h12',minus:'M6 12h12',edit:'m5 15 11-11 4 4L9 19H5v-4Zm8-8 4 4',warning:'m12 3 10 18H2L12 3Zm0 6v5m0 3h.01',alert:'M12 6v8m0 3h.01',diamond:'m12 3 9 9-9 9-9-9 9-9Z',prohibited:'M5 5l14 14M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0',
} as const;
export type IconName=keyof typeof paths;
export function Icon({name,className=''}:{name:IconName;className?:string}){
  if(name==='brand')return <svg className={`ui-icon brand-symbol ${className}`} data-icon={name} viewBox="0 0 48 40" aria-hidden="true" focusable="false"><path fill="#45c7ef" d="M4 10 20 2a8 8 0 0 1 7 0l17 8c3 2 3 5 0 7l-17 8a8 8 0 0 1-7 0L4 17c-4-2-4-5 0-7Z"/><path fill="#4475ef" d="m4 25 16-8a8 8 0 0 1 7 0l17 8c3 2 3 5 0 7l-17 8a8 8 0 0 1-7 0L4 32c-4-2-4-5 0-7Z"/><circle cx="31" cy="15" r="2.4" fill="white"/><circle cx="19" cy="29" r="2.4" fill="white"/></svg>;
  return <svg className={`ui-icon ${className}`} data-icon={name} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">{['help','info','check','plus','minus','alert'].includes(name)&&<circle cx="12" cy="12" r="10"/>}<path d={paths[name]}/></svg>;
}
