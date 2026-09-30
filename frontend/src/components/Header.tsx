import {Icon} from './Icon';
interface Props {projectId?:string;saved?:boolean;demo?:boolean;onOpen:()=>void;onImport:()=>void}
export default function Header({projectId,demo=false,onOpen,onImport}:Props){
  const project=demo?'Firewall-Migration-01':projectId?.slice(0,18)||'Untitled';
  return <header className="figma-header">
    <div className="figma-brand"><span className="brand-mark"><Icon name="brand"/></span><h1>ConfigMorph</h1><span className="brand-divider"/><div className="brand-copy"><b>Network Configuration Migration</b><span>Translate. Validate. Migrate with Confidence.</span></div></div>
    <div className="figma-project"><span>Project:</span><button className="project-select" aria-label={`Project: ${project}`} onClick={onOpen}>{project}<Icon name="chevron"/></button>
      {projectId&&!demo?<a href={`/api/projects/${projectId}/export`}><Icon name="save"/>Save</a>:<button disabled={demo} title={demo?'Visual fixture only':'Convert before saving a project'}><Icon name="save"/>Save</button>}
      <button onClick={onImport}><Icon name="folder"/>Load</button>
      <details className="project-menu"><summary aria-label="Project menu"><Icon name="menu"/></summary><button onClick={onOpen}><Icon name="folder"/>Open project by ID</button></details>
    </div>
  </header>;
}
