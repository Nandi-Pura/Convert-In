import {renderToStaticMarkup} from 'react-dom/server';
import {describe,expect,it} from 'vitest';
import Header from './Header';
import {CodeEditor,ConversionSuccess,ConversionSummary} from './LockedPanels';
import {referenceResult} from '../referenceFixture';
import InvestigationTabs,{tabNames} from './InvestigationTabs';
import {VendorBrand,vendorDisplayName} from './VendorBrand';
describe('reference workbench shell',()=>{
  it('uses one bounded vendor identity component for known and future vendors',()=>{
    const names=['PALO_ALTO','FORTINET','CISCO','CHECK_POINT','JUNIPER','HPE_ARUBA','F5','Future Vendor'];
    const html=names.map(vendor=>renderToStaticMarkup(<VendorBrand vendor={vendor}/>)).join('');
    expect(html.match(/class="vendor-brand"/g)).toHaveLength(names.length);
    for(const vendor of names)expect(html).toContain(`aria-label="${vendorDisplayName(vendor)}"`);
    expect(html.match(/--vendor-max-width:148px/g)).toHaveLength(names.length);
    expect(html.match(/--vendor-translate-x:0px/g)).toHaveLength(names.length);
    expect(html.match(/--vendor-translate-y:0px/g)).toHaveLength(names.length);
    expect(html).not.toContain('class="vendor-brand paloalto"');
    expect(html).not.toContain('class="vendor-brand fortinet"');
  });
  it('renders the reference project actions and identifies demo data',()=>{
    const html=renderToStaticMarkup(<Header demo onOpen={()=>{}} onImport={()=>{}}/>);
    for(const label of ['ConfigMorph','Network Configuration Migration','Translate. Validate. Migrate with Confidence.','Project: Firewall-Migration-01','Save','Load','Project menu'])expect(html).toContain(label);
    expect(html).not.toContain('sidebar');
    expect(html).not.toContain('Saved');
  });
  it('renders the final five accessible tabs in locked order',()=>{
    expect(tabNames).toEqual(['Raw Comparison','Semantic Diff','Migration Plan','Candidate Configuration','Evidence']);
    const html=renderToStaticMarkup(<InvestigationTabs active="Raw Comparison" findings={13480} onChange={()=>{}}/>);
    expect(html.match(/role="tab"/g)).toHaveLength(5);
    expect(html).not.toContain('Findings');
    expect(html).not.toContain('13,480');
    expect(html).toContain('aria-controls=');
  });
});


describe('locked conversion presentation',()=>{
  it('uses the approved success percentage in the isolated fixture',()=>{
    const html=renderToStaticMarkup(<ConversionSuccess demo/>);
    expect(html).toContain('82%');
    expect(html).toContain('stroke-dasharray="82 18"');
    expect(html).not.toContain('41,820');
  });
  it('uses converted source lines for real results and leaves missing results unclaimed',()=>{
    const html=renderToStaticMarkup(<ConversionSuccess result={referenceResult}/>);
    expect(html).toContain('62.3 percent of source lines converted');
    expect(html).not.toContain('82%');
    const empty=renderToStaticMarkup(<ConversionSuccess/>);
    expect(empty).toContain('Conversion results unavailable until Convert completes');
    expect(empty).not.toContain('stroke-dasharray');
  });
  it('preserves blank configuration lines without inserting the empty-state prompt',()=>{
    const html=renderToStaticMarkup(<CodeEditor text={'first\n\nthird'} title="Source Configuration"/>);
    expect(html).not.toContain('Import a source configuration to begin.');
    expect(html.match(/class="editor-line"/g)).toHaveLength(3);
  });
  it('renders backend conversion summary values without fixture fallbacks',()=>{
    const result={...referenceResult,conversion_summary:{added:2,modified:3,removed:1,unsupported:4,needs_review:5}};
    const html=renderToStaticMarkup(<ConversionSummary result={result}/>);
    for(const value of ['>2<','>3<','>1<','>4<','>5<'])expect(html).toContain(value);
    expect(html).not.toContain('>12<');
  });
});
