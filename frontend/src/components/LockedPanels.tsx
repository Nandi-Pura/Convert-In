import {useMemo,useState} from 'react';
import {Icon,type IconName} from './Icon';
import {visualFixture} from '../visualFixture';
import type {Result} from '../types';
import {VendorBrand} from './VendorBrand';

type RowStatus=''|'converted'|'modified'|'review'|'removed'|'unsupported';

export function CodeEditor({text,title,candidate=false,info=false,emptyMessage,showHeader=true,vendor,lineCount,statuses=[],search='',changesOnly=false,scrollRef,onEditorScroll}:{text:string;title:string;candidate?:boolean;info?:boolean;emptyMessage?:string;showHeader?:boolean;vendor?:string;lineCount?:number;statuses?:string[];search?:string;changesOnly?:boolean;scrollRef?:(element:HTMLDivElement|null)=>void;onEditorScroll?:(element:HTMLDivElement)=>void}){
  const allLines=useMemo(()=>text.split('\n').map((line,index)=>({line,index,status:(statuses[index]||'') as RowStatus})),[text,statuses]);
  const filtered=useMemo(()=>allLines.filter(item=>(!search||item.line.toLowerCase().includes(search.toLowerCase()))&&(!changesOnly||!statuses.length||Boolean(item.status))),[allLines,search,changesOnly,statuses.length]);
  const[top,setTop]=useState(0),start=Math.max(0,Math.floor(top/20)-4),visible=filtered.slice(start,start+80);
  return <section className={`locked-editor ${candidate?'candidate-editor':''}`} aria-label={title}>{showHeader&&<header><h3>{vendor?<VendorBrand vendor={vendor} compact/>:<Icon name={candidate?'check':'file'}/>}<span>{title}</span></h3>{lineCount!=null&&<b>{lineCount.toLocaleString()} lines</b>}{info&&<span><Icon name="info"/>After you click Convert, the results will appear in the tabs below.</span>}</header>}<div className="editor-lines" ref={scrollRef} tabIndex={0} onScroll={event=>{setTop(event.currentTarget.scrollTop);onEditorScroll?.(event.currentTarget)}}><div style={{height:Math.max(filtered.length,1)*20,position:'relative'}}>{visible.map((item,i)=><div className={item.status?`editor-line ${item.status}`:'editor-line'} key={item.index} style={{top:(start+i)*20}}><i/><span>{item.index+1}</span><code>{item.line||(text?' ':emptyMessage||'Import a source configuration to begin.')}</code></div>)}{!visible.length&&<div className="editor-empty">{text?'No matching configuration lines.':emptyMessage||'Import a source configuration to begin.'}</div>}</div></div></section>;
}

const legend=[['Converted','converted'],['Modified','modified'],['Needs Review','review'],['Removed','removed'],['Unsupported','unsupported']] as const;
export function ConversionSuccess({demo=false,result}:{demo?:boolean;result?:Result}){
  const accounting=result?.line_accounting;
  const success=demo?82:accounting&&accounting.total_analyzed_lines>0?Math.round(accounting.converted_lines/accounting.total_analyzed_lines*1000)/10:undefined;
  const values=demo?visualFixture.legend:[accounting?accounting.converted_lines.toLocaleString():'—','—',accounting?accounting.review_lines.toLocaleString():'—','—',accounting?accounting.unsupported_lines.toLocaleString():'—'];
  return <aside className="conversion-success"><h3>Conversion Success</h3><div className="success-content"><div className="donut" role="img" aria-label={demo?'Visual fixture: 82 percent converted. Not compatibility or confidence.':success===undefined?'Conversion results unavailable until Convert completes':`${success} percent of source lines converted`}><svg viewBox="0 0 120 120" aria-hidden="true"><circle cx="60" cy="60" r="46" fill="none" stroke="#e3e9f1" strokeWidth="12"/>{success!==undefined&&<circle cx="60" cy="60" r="46" fill="none" stroke="#14b86e" strokeWidth="12" strokeLinecap="round" pathLength="100" strokeDasharray={`${success} ${100-success}`} transform="rotate(-90 60 60)"/>}</svg><b>{success===undefined?'—':`${success}%`}</b></div><div className="donut-legend">{legend.map(([label,tone],i)=><div key={label}><i className={tone}/><span>{label}</span><b>{values[i]}</b></div>)}</div></div></aside>;
}

export function ConversionSummary({demo=false,result}:{demo?:boolean;result?:Result}){
  const rows:[string,string,IconName,string,keyof NonNullable<Result['conversion_summary']>][]=[
    ['Added','New configuration items in target','plus','added','added'],['Modified','Configuration items with changes','edit','modified','modified'],['Removed','Configuration items not migrated','trash','removed','removed'],['Unsupported','Configuration items with no equivalent','prohibited','unsupported','unsupported'],['Needs Review','Configuration items requiring manual review','warning','review','needs_review']
  ];
  return <aside className="conversion-summary"><h3>Conversion Summary</h3><div>{rows.map(([label,detail,icon,tone,key],i)=>{const value=result?.conversion_summary?.[key];return <article key={label}><span className={`summary-icon ${tone}`}><Icon name={icon}/></span><div><b>{label}</b><small>{detail}</small></div><strong>{demo?visualFixture.counts[i]:value==null?'—':value}</strong></article>})}</div></aside>;
}
