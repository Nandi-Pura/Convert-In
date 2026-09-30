import {Icon,type IconName} from './Icon';
export const tabNames=['Raw Comparison','Semantic Diff','Migration Plan','Candidate Configuration','Evidence'] as const;
export type TabName=typeof tabNames[number];
const icons:IconName[]=['compare','branch','list','check','file'];
export default function InvestigationTabs({active,onChange}:{active:TabName;findings?:number;onChange:(tab:TabName)=>void}){
  return <div className="figma-tabs" role="tablist" aria-label="Investigation views">{tabNames.map((tab,i)=><button key={tab} id={`result-tab-${i}`} role="tab" aria-label={tab} aria-selected={active===tab} aria-controls="result-panel" tabIndex={active===tab?0:-1} className={active===tab?'active':''} onClick={()=>onChange(tab)} onKeyDown={e=>{const next=e.key==='ArrowRight'?(i+1)%5:e.key==='ArrowLeft'?(i+4)%5:e.key==='Home'?0:e.key==='End'?4:-1;if(next>=0){e.preventDefault();onChange(tabNames[next]);document.getElementById(`result-tab-${next}`)?.focus()}}}><Icon name={icons[i]}/>{tab}</button>)}</div>;
}
