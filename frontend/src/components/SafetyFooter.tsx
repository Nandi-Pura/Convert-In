import {Icon} from './Icon';
export default function SafetyFooter({projectId,demo=false}:{projectId?:string;demo?:boolean}){
  return <footer className="figma-footer"><span><Icon name="warning"/>CANDIDATE CONFIGURATION — ENGINEER REVIEW REQUIRED · No device deployment</span><span>{demo?'Visual fixture only · ':''}Local Only{projectId?` · Project: ${projectId.slice(0,16)}`:''}</span></footer>;
}
