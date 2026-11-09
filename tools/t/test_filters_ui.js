/* Lead validation tooling: DOM logic checks, not a real browser/AT substitute. */
async function runFiltersUi(fixture) {
  const clone=value=>JSON.parse(JSON.stringify(value));
  const assert=(value,message)=>{if(!value)throw new Error(message);};
  const results=[];
  for(const mode of ['editable','mixed','readonly','historical','unmanaged']) {
    const roots=new Map(), documentHandlers={}, windowHandlers={}, posts=[];
    let document;
    class Node {
      constructor(tag='div') {
        this.tagName=tag.toUpperCase();this.children=[];this.parentNode=null;this.dataset={};this.style={};
        this.attributes={};this.handlers={};this.textContent='';this.value='';this.checked=false;
        this.indeterminate=false;this.disabled=false;this.hidden=false;this.open=false;
        this.classList={add(){},remove(){},toggle(){}};
      }
      append(...values){for(const child of values){if(child==null)continue;child.parentNode=this;this.children.push(child);}}
      appendChild(child){this.append(child);return child;}
      replaceChildren(...values){for(const child of this.children)child.parentNode=null;this.children=[];this.append(...values);}
      addEventListener(type,handler){(this.handlers[type]||(this.handlers[type]=[])).push(handler);}
      setAttribute(key,value){this.attributes[key]=String(value);}
      contains(node){for(let at=node;at;at=at.parentNode)if(at===this)return true;return false;}
      getBoundingClientRect(){const body=this.className==='filter-help-body';return {right:300,bottom:120,width:body?Math.min(448,document.documentElement.clientWidth-24):26,height:body?160:26};}
    }
    const buttonIds=['save-settings','discard-settings','reset-settings','preview','apply','apply-settings','add-exception'];
    const get=id=>{
      if(!roots.has(id))roots.set(id,new Node(buttonIds.includes(id)?'button':id==='native-level'?'select':id==='ip-policy'||id==='acknowledge-coverage'?'input':id==='profile-fields'||id==='exception-fields'?'fieldset':'div'));
      return roots.get(id);
    };
    const fields=get('profile-fields');fields.disabled=true;
    for(const id of ['filter-list','advanced-fields','ip-policy','ip-policy-help','native-level','native-level-help'])fields.append(get(id));
    function all(){const found=new Set();function walk(n){if(found.has(n))return;found.add(n);for(const c of n.children)walk(c);}for(const n of roots.values())walk(n);return [...found];}
    function disabled(node){if(!['INPUT','SELECT','BUTTON','TEXTAREA','FIELDSET'].includes(node.tagName))return false;for(let n=node;n;n=n.parentNode)if(n.disabled&&(n===node||n.tagName==='FIELDSET'))return true;return false;}
    function emit(node,type,extra={}) {
      if(disabled(node))return;
      const event=Object.assign({type,target:node,preventDefault(){this.defaultPrevented=true;}},extra);
      for(let current=node;current;current=current.parentNode){for(const fn of current.handlers[type]||[])fn(event);if(current['on'+type])current['on'+type](event);}
      return event;
    }
    function emitDocument(type,extra={}){const event=Object.assign({type,preventDefault(){this.defaultPrevented=true;}},extra);for(const fn of documentHandlers[type]||[])fn(event);}
    document={getElementById:get,createElement:tag=>new Node(tag),createTextNode:text=>Object.assign(new Node('#text'),{textContent:text}),
      documentElement:{clientWidth:390,clientHeight:844},activeElement:null,
      addEventListener(type,fn){(documentHandlers[type]||(documentHandlers[type]=[])).push(fn);},
      querySelectorAll(selector){return all().filter(n=>selector==='[data-filter]'?n.dataset.filter:selector==='[data-rule]'?n.dataset.rule:false);}};
    const profile=clone(fixture.profile),catalogue=clone(fixture.catalogue);
    const optional=catalogue.components.find(component=>component.family===null);
    if(optional)optional.impact_note='Catalogue-owned scope note fixture';
    const multi=catalogue.families.map(f=>({family:f,members:catalogue.components.filter(c=>c.family===f.key)})).filter(g=>g.members.length>1);
    if(mode==='mixed')profile.filters[multi[0].members[0].key]=false;
    const expectedInitial=clone(profile.filters);
    const state={site:'example.test',managed:mode!=='unmanaged',profile_id:'a'.repeat(64),generation:'20261109T120000Z-12345678',generated_utc:'2026-11-09T12:00:00Z',
      applied:mode==='unmanaged'?null:profile,default_profile:clone(fixture.profile),filter_catalogue:catalogue,pending:null,
      browser_access:{allow_updates:mode!=='readonly'},coverage:{known_previous_input:true,retained_days:['2026-11-01'],needs_acknowledgement:false},
      effective:fixture.effective,effective_by_month:{},jobs:[],totals:{'2026-11':{unique:1,visits:1,pages:2,hits:3,bytes:100}},view_totals:{},matched_requests:{}};
    if(optional)state.evidence_classes={[optional.key]:{by_month:{'2026-11':{matched_requests:1,exclusive_requests:0,overlapping_requests:0}}}};
    get('filters-state').textContent=JSON.stringify(state);get('filters-main').dataset.historical=String(mode==='historical');
    const fetch=async(url,options)=>{
      if(options.method==='POST'){
        const body=JSON.parse(options.body);posts.push({url,body});
        if(url.endsWith('/save'))state.pending={profile:clone(body.profile)};
      }
      return {ok:true,json:async()=>url==='/vstats-control/session'?{csrf:'synthetic'}:url.endsWith('/history')?[]:clone(state)};
    };
    const window={addEventListener(type,fn){(windowHandlers[type]||(windowHandlers[type]=[])).push(fn);}};
    const execute=new Function('document','window','fetch','navigator','location','URLSearchParams','crypto',fixture.js);
    execute(document,window,fetch,{clipboard:{writeText:async()=>{}}},{protocol:'https:',search:'',hash:'#settings'},class{get(){return null;}},{getRandomValues(value){value.fill(1);return value;}});
    const settle=async()=>{for(let i=0;i<60;i++)await Promise.resolve();};await settle();
    assert(!get('filter-message').textContent,mode+': '+get('filter-message').textContent);
    if(optional&&mode!=='unmanaged')assert(all().some(node=>node.textContent.includes(optional.impact_note)),mode+': scope note must come from catalogue');
    const inputs=()=>document.querySelectorAll('[data-filter]');
    const values=()=>Object.fromEntries(inputs().map(n=>[n.dataset.filter,n.checked]));
    assert(inputs().length===catalogue.components.length,mode+': each component must occur once');
    assert(catalogue.components.every(c=>values()[c.key]===(mode==='unmanaged'?fixture.profile.filters:expectedInitial)[c.key]),mode+': load changed a choice');
    const main=get('filter-list');
    const parameterKeys=document.querySelectorAll('[data-rule]').map(n=>n.dataset.rule+'/'+n.dataset.key);
    assert(new Set(parameterKeys).size===parameterKeys.length,mode+': duplicate shared parameters');
    for(const family of catalogue.families){
      const members=catalogue.components.filter(c=>c.family===family.key);if(!members.length)continue;
      if(members.length===1)assert(inputs().filter(n=>n.dataset.filter===members[0].key&&main.contains(n)).length===1,mode+': singleton must be on main page');
      else assert(all().filter(n=>n.dataset.filterFamily===family.key).length===1,mode+': missing family');
    }
    for(const component of catalogue.components){
      const triggers=all().filter(n=>n.tagName==='SUMMARY'&&n.attributes['aria-label']==='About '+component.label);
      assert(triggers.length===1,mode+': missing or duplicate component help '+component.key);
      const trigger=triggers[0],help=trigger.parentNode,body=help.children[1],before=JSON.stringify(values());
      for(let node=trigger.parentNode;node;node=node.parentNode)assert(node.tagName!=='LABEL',mode+': help inside checkbox label');
      emit(help,'mouseenter');assert(help.open,mode+': hover help');
      emitDocument('pointerdown',{target:body});assert(help.open,mode+': help must remain hoverable');
      emit(help,'mouseleave');assert(!help.open,mode+': hover dismissal');
      emit(trigger,'focusin');assert(help.open,mode+': keyboard focus help');
      const beforeScroll=trigger.getBoundingClientRect();
      trigger.getBoundingClientRect=()=>Object.assign({},beforeScroll,{bottom:240});
      for(const listener of windowHandlers.scroll||[])listener({});
      assert(help.open,mode+': focus-triggered scroll must preserve help');
      assert(Number.parseFloat(body.style.top)===240,mode+': scroll must reposition existing help');
      emitDocument('keydown',{key:'Escape'});assert(!help.open,mode+': Escape dismissal');
      for(const listener of windowHandlers.scroll||[])listener({});assert(!help.open,mode+': scroll after Escape must not reopen help');
      emit(trigger,'focusout',{relatedTarget:get('return-report')});
      emit(trigger,'click');assert(help.open,mode+': touch-like help tap');
      assert(Number.parseFloat(body.style.left)>=12&&Number.parseFloat(body.style.top)>=12,mode+': help positioning');
      emitDocument('pointerdown',{target:get('return-report')});assert(!help.open,mode+': outside dismissal');
      assert(before===JSON.stringify(values()),mode+': help toggled a filter');
    }
    if(mode==='readonly'||mode==='historical'){
      assert(fields.disabled,mode+': settings should be disabled');
      const first=inputs()[0],before=first.checked;emit(first,'change');assert(first.checked===before,mode+': disabled control');
      assert(get('reprocessing-actions').hidden,mode+': reprocessing should be hidden');
    } else {
      assert(!fields.disabled,mode+': editable settings unexpectedly disabled');
      const group=multi[0],familyInput=()=>all().find(n=>n.dataset.filterFamily===group.family.key);
      if(mode==='mixed')assert(familyInput().indeterminate,mode+': mixed state must be visible');
      const outside=Object.fromEntries(Object.entries(values()).filter(([key])=>!group.members.some(c=>c.key===key)));
      familyInput().checked=true;emit(familyInput(),'change');assert(group.members.every(c=>values()[c.key]),mode+': mixed/unchecked activation must enable members');
      assert(!familyInput().indeterminate,mode+': all state');
      familyInput().checked=false;emit(familyInput(),'change');assert(group.members.every(c=>!values()[c.key]),mode+': checked activation must disable members');
      assert(Object.entries(outside).every(([key,value])=>values()[key]===value),mode+': family changed another family');
      const member=inputs().find(n=>n.dataset.filter===group.members[0].key);member.checked=true;emit(member,'change');
      assert(familyInput().indeterminate,mode+': individual change must update family');
      const summaries=all().filter(n=>n.className==='filter-effective'&&n.textContent.startsWith('Current report: '));
      assert(summaries.length===multi.length,mode+': group status summaries');
      for(const policy of ['ip_policy','native_level','aggressive_comparison']){
        if(policy==='aggressive_comparison'&&!profile.classifier.scheduled_automation)continue;
        const trigger=all().find(n=>n.tagName==='SUMMARY'&&n.attributes['aria-label']==='About '+catalogue.policies[policy].label);
        assert(trigger,mode+': missing policy help '+policy);
        const before=JSON.stringify(values());emit(trigger,'click');assert(trigger.parentNode.open,mode+': policy help');
        emitDocument('keydown',{key:'Escape'});assert(before===JSON.stringify(values()),mode+': policy help changed filters');
      }
      const aggressive=document.querySelectorAll('[data-rule]').find(n=>n.dataset.key==='aggressive_comparison');
      if(aggressive){aggressive.checked=true;emit(aggressive,'input');}
      const before=clone(values());emit(get('save-settings'),'click');await settle();
      assert(posts.length===1&&posts[0].url.endsWith('/save'),mode+': expected one pending save');
      assert(JSON.stringify(posts[0].body.profile.filters)===JSON.stringify(Object.fromEntries(Object.keys(fixture.profile.filters).map(key=>[key,before[key]]))),mode+': save changed choices');
      assert(familyInput().indeterminate,mode+': mixed state lost after refresh');
      if(aggressive)assert(posts[0].body.profile.classifier.scheduled_automation.aggressive_comparison===1,mode+': comparison switch serialization');
      assert(documentHandlers.keydown.length===1&&documentHandlers.pointerdown.length===1,mode+': refresh leaked document listeners');
    }
    results.push({mode,pass:true,components:catalogue.components.length,mainFamilies:catalogue.families.length});
  }
  return results;
}

if(typeof module!=='undefined')module.exports=runFiltersUi;
if(typeof require==='function'&&require.main===module){
  const path=require('path'),child=require('child_process'),root=path.resolve(__dirname,'../..');
  const script="import json,os,sys;from pathlib import Path;sys.path.insert(0,'tools');import vstats_filters as v;app=os.getcwd();perl=os.environ.get('VSTATS_TEST_PERL','perl');p=v.validate_profile(v.defaults(app,perl),app,perl);print(json.dumps({'js':Path('wwwroot/js/filters.js').read_text(encoding='utf-8'),'profile':p,'catalogue':v.filter_catalogue(),'effective':v.filter_status(p)},ensure_ascii=True))";
  const raw=child.execFileSync(process.env.VSTATS_TEST_PYTHON||'python3',['-B','-c',script],{cwd:root,env:Object.assign({},process.env,{LC_ALL:'C',LANG:'C',PYTHONDONTWRITEBYTECODE:'1'}),maxBuffer:4*1024*1024});
  runFiltersUi(JSON.parse(raw.toString())).then(value=>console.log(JSON.stringify(value))).catch(error=>{console.error(error.stack);process.exitCode=1;});
}
