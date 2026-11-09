/* Optional static-publisher control UI. Credentials stay in page memory only. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let state = JSON.parse($('filters-state').textContent);
  let profile = structuredCopy(state.applied || state.default_profile);
  let csrf = null, editable = false, busy = false, poll = null, coverage = state.coverage;
  const site = state.site, base = '/vstats-control/sites/' + encodeURIComponent(site) + '/';
  const historical = $('filters-main').dataset.historical === 'true';
  let catalogue, names, activeHelp = null, helpSerial = 0;
  let filterInputs = new Map(), familyInputs = [];
  function structuredCopy(v) { return JSON.parse(JSON.stringify(v)); }
  function readCatalogue() {
    catalogue = state.filter_catalogue;
    names = Object.fromEntries(catalogue.components.map(row => [row.key, [row.label, row.summary]]));
  }
  readCatalogue();
  function node(tag, text, cls) { const n = document.createElement(tag); if(text !== undefined) n.textContent = text; if(cls) n.className = cls; return n; }
  function message(text) { $('filter-message').className = text ? 'filters-alert' : ''; $('filter-message').textContent = text; }
  function edited() { $('profile-status').textContent = 'Unsaved changes'; }
  function context() {
    const months=Object.keys(state.totals||{}).sort(), returning=new URLSearchParams(location.search).get('return');
    let month=months[months.length-1],filename='awstats.'+site+'.html';
    if(returning&&returning.startsWith('/vstats/'+site+'/')){
      const parts=new URL(returning,location.origin).pathname.split('/');
      const selected=parts.find(p=>months.includes(p));if(selected)month=selected;
      const candidate=parts[parts.length-1];const topics=['','alldomains','allhosts','allrobots','browserdetail','downloads','errors400','errors403','errors404','keyphrases','keywords','lasthosts','lastrobots','osdetail','refererpages','refererse','session','unknownbrowser','unknownip','unknownos','urldetail','urlentry','urlexit'];
      if(topics.some(t=>candidate==='awstats.'+site+(t?'.'+t:'')+'.html'))filename=candidate;
    }return{month,filename};
  }
  async function api(path, body) {
    if(location.protocol !== 'https:') throw new Error('Open Filters over HTTPS to change settings or reprocess logs.');
    const headers = {};
    if(body !== undefined) { headers['Content-Type']='application/json'; headers['X-VStats-CSRF']=csrf; }
    const response = await fetch(path, {method:body===undefined?'GET':'POST', headers, body:body===undefined?undefined:JSON.stringify(body),cache:'no-store',credentials:'same-origin'});
    const result = await response.json(); if(!response.ok) throw new Error(result.error || 'Request failed'); return result;
  }
  function authorization() {
    const enabled = Boolean(editable && csrf && !busy && !historical);
    $('profile-fields').disabled = !enabled; $('exception-fields').disabled = !enabled;
    for(const id of ['save-settings','discard-settings','reset-settings','preview','apply','apply-settings']) $(id).disabled = !enabled;
    $('readonly-note').hidden = editable;
    $('settings-actions').hidden = !editable || historical; $('reprocessing-actions').hidden = !editable || historical;
    $('exception-fields').hidden = !editable || historical;
    if(coverage && coverage.needs_acknowledgement && !$('acknowledge-coverage').checked) { $('apply').disabled = true; $('apply-settings').disabled = true; }
  }
  function drawCoverage(value) {
    coverage = value; const area = $('coverage-description'); area.replaceChildren();
    if(!value) {area.append(node('p','Input coverage has not been recorded. Run Preview before applying.'));return;}
    const days=value.retained_days || [];
    area.append(node('p', days.length ? 'Retained input: '+days[0]+' through '+days[days.length-1]+' ('+days.length+' UTC days).' : 'Retained input will be determined by the first Preview.'));
    if(value.missing_previous_days && value.missing_previous_days.length) area.append(node('p','Previously reported days no longer retained: '+value.missing_previous_days.join(', ')));
    if(value.changed_previous_days && value.changed_previous_days.length) area.append(node('p','Previously used input has changed: '+value.changed_previous_days.join(', ')));
    if(!value.known_previous_input) area.append(node('p','The old generation’s source coverage cannot be established. Before values are unavailable; only the listed retained input can be rebuilt.'));
    const details=node('details');details.append(node('summary','List retained UTC days'));details.append(node('p',days.join(', ') || 'Not yet determined'));area.append(details);
    $('coverage-confirm').hidden=!value.needs_acknowledgement; $('acknowledge-coverage').checked=false; authorization();
  }
  function help(title, text) {
    const root=node('details',undefined,'filter-help'), trigger=node('summary','?'), body=node('div',text,'filter-help-body');
    body.id='filter-help-'+(++helpSerial);body.setAttribute('role','tooltip');
    trigger.setAttribute('aria-label','About '+title);trigger.setAttribute('aria-describedby',body.id);
    root.append(trigger,body);
    let hovered=false,focused=false,pinned=false;
    const entry={root,close(){root.open=false;pinned=false;if(activeHelp===entry)activeHelp=null;}};
    const show=()=>{
      if(activeHelp&&activeHelp!==entry)activeHelp.close();root.open=true;activeHelp=entry;
      const anchor=trigger.getBoundingClientRect(), size=body.getBoundingClientRect(), viewport=document.documentElement;
      body.style.left=Math.max(12,Math.min(anchor.right-size.width,viewport.clientWidth-size.width-12))+'px';
      body.style.top=Math.max(12,Math.min(anchor.bottom,viewport.clientHeight-size.height-12))+'px';
    };
    root.addEventListener('mouseenter',()=>{hovered=true;show();});
    root.addEventListener('mouseleave',()=>{hovered=false;if(!focused&&!pinned)entry.close();});
    root.addEventListener('focusin',()=>{focused=true;show();});
    root.addEventListener('focusout',event=>{if(!root.contains(event.relatedTarget)){focused=false;if(!hovered)entry.close();}});
    trigger.addEventListener('click',event=>{event.preventDefault();pinned=!pinned;if(pinned)show();else entry.close();});
    return root;
  }
  document.addEventListener('keydown',event=>{if(event.key==='Escape'&&activeHelp){event.preventDefault();activeHelp.close();}});
  document.addEventListener('pointerdown',event=>{if(activeHelp&&!activeHelp.root.contains(event.target))activeHelp.close();});
  window.addEventListener('resize',()=>{if(activeHelp)activeHelp.close();});
  window.addEventListener('scroll',()=>{if(activeHelp)activeHelp.close();});
  function choice(item, host) {
    const row=node('div',undefined,'filters-option'), label=node('label',undefined,'filter-setting'), input=node('input');
    input.type='checkbox';input.checked=profile.filters[item.key];input.dataset.filter=item.key;
    input.addEventListener('change',()=>{updateFamilies();edited();});
    filterInputs.set(item.key,input);
    const content=node('span');content.append(node('strong',item.label),node('small',item.summary));
    label.append(input,content);
    row.append(label,node('span',(state.effective||{})[item.key]||'Not recorded','filter-effective'),help(item.label,item.help));
    host.append(row);
  }
  function updateFamilies() {
    for(const family of familyInputs) {
      const selected=family.members.filter(item=>filterInputs.get(item.key).checked).length;
      family.input.checked=selected===family.members.length;
      family.input.indeterminate=selected>0&&selected<family.members.length;
      const counts={active:0,needs:0,off:0,unknown:0};
      for(const item of family.members)counts[catalogue.status_classes[(state.effective||{})[item.key]]||'unknown']++;
      let summary='Current report: '+counts.active+' active; '+counts.needs+' need configuration, evidence or capacity';
      if(counts.off)summary+='; '+counts.off+' off';
      if(counts.unknown)summary+='; '+counts.unknown+' not recorded';
      family.status.textContent=summary;
    }
  }
  function parameters(item, host, emitted) {
    const rule=item.section;if(!rule||emitted.has(rule))return;emitted.add(rule);
    const box=node('details',undefined,'filter-parameters');box.append(node('summary','Parameters: '+(item.section_label||item.label)));
    const grid=node('div',undefined,'filters-advanced-grid');
    for(const [key,value] of Object.entries(profile.classifier[rule])) {
      if(key==='enabled'||key==='retrospective_enabled')continue;
      const control=node('div',undefined,'filter-parameter'), label=node('label'), input=node(Array.isArray(value)?'textarea':'input');
      let title=(key==='retrospective_months'||key==='months')?'UTC months (YYYY-MM, one per line)':key.replace(/_/g,' ');
      let description=(item.parameter_help||{})[key]||catalogue.parameter_help[key];
      input.dataset.rule=rule;input.dataset.key=key;
      if(key==='aggressive_comparison') {
        const policy=catalogue.policies.aggressive_comparison;title=policy.label;description=policy.summary;
        input.type='checkbox';input.checked=Boolean(value);input.dataset.switch='true';
        label.append(input,node('span',title));control.append(label,help(title,policy.help));
      } else {
        if(Array.isArray(value)){input.value=value.join('\n');input.dataset.array='true';}
        else {input.type='number';input.step='1';input.min='0';input.value=value;}
        label.append(node('span',title),input);control.append(label);
      }
      if(!description)throw new Error('Missing parameter help for '+rule+'/'+key);
      const note=node('small',description,'filter-parameter-help');note.id='filter-parameter-'+rule+'-'+key;
      input.setAttribute('aria-describedby',note.id);control.append(note);
      input.addEventListener('input',edited);grid.append(control);
    }
    box.append(grid);host.append(box);
  }
  function drawForm() {
    if(activeHelp)activeHelp.close();readCatalogue();filterInputs=new Map();familyInputs=[];
    $('site-label').textContent=site; $('applied-description').textContent=(state.applied?'Applied profile '+state.profile_id.slice(0,12):'Unverified profile; Filters have not been applied.')+' · Report generation '+state.generation+' · '+state.generated_utc;
    $('profile-status').textContent=state.pending?'Pending settings':state.applied?'Applied settings':'Defaults pending';$('profile-note').textContent=state.note||'';
    const list=$('filter-list'),advanced=$('advanced-fields');list.replaceChildren();advanced.replaceChildren();
    const emitted=new Set();
    for(const family of catalogue.families) {
      const members=catalogue.components.filter(item=>item.family===family.key);if(!members.length)continue;
      const section=node('section',undefined,'filter-family-details');
      if(members.length===1)choice(members[0],list);
      else {
        const row=node('div',undefined,'filters-option'),label=node('label',undefined,'filter-setting'),input=node('input');
        input.type='checkbox';input.dataset.filterFamily=family.key;
        const content=node('span');content.append(node('strong',family.label),node('small','Adjust individual rules in Advanced.'));
        label.append(input,content);const status=node('span',undefined,'filter-effective');
        row.append(label,status,help(family.label,family.help));list.append(row);
        input.addEventListener('change',()=>{for(const item of members)filterInputs.get(item.key).checked=input.checked;updateFamilies();edited();});
        familyInputs.push({input,status,members});section.append(node('h3',family.label));
      }
      for(const item of members) {
        if(members.length>1)choice(item,section);
        parameters(item,section,emitted);
      }
      if(section.children.length)advanced.append(section);
    }
    const optional=catalogue.components.filter(item=>!item.family);
    if(optional.length) {
      const section=node('section',undefined,'filter-family-details');section.append(node('h3','Optional comparisons'));
      for(const item of optional){choice(item,section);parameters(item,section,emitted);}advanced.append(section);
    }
    const ip=catalogue.policies.ip_policy,native=catalogue.policies.native_level;
    $('ip-policy-title').textContent=ip.label;$('ip-policy-description').textContent=ip.summary;
    $('ip-policy-help').replaceChildren(help(ip.label,ip.help));$('ip-policy').checked=profile.exclude_automated_ips;
    $('native-level-label').textContent=native.label;$('native-level-description').textContent=native.summary;
    $('native-level-help').replaceChildren(help(native.label,native.help));$('native-level').replaceChildren();
    for(const option of native.options){const nodeOption=node('option',option.label);nodeOption.value=String(option.value);$('native-level').append(nodeOption);}
    $('native-level').value=profile.native_level;updateFamilies();
    const periods=$('period-status');periods.replaceChildren();const table=node('table'),heading=node('tr');heading.append(node('th','UTC month'));Object.values(names).forEach(n=>heading.append(node('th',n[0])));table.append(heading);for(const month of Object.keys(state.effective_by_month||{}).sort().reverse()){const row=node('tr');row.append(node('td',month));Object.keys(names).forEach(key=>row.append(node('td',state.effective_by_month[month][key]||'Not recorded')));table.append(row);}periods.append(table);
    drawExceptions();drawCoverage(state.coverage);authorization();drawLinks();drawJobs(state.jobs||[]);drawCurrentImpact();
  }
  function collect() {
    const result=structuredCopy(profile);
    document.querySelectorAll('[data-filter]').forEach(input=>result.filters[input.dataset.filter]=input.checked);
    result.exclude_automated_ips=$('ip-policy').checked;result.native_level=Number($('native-level').value);
    document.querySelectorAll('[data-rule]').forEach(input=>result.classifier[input.dataset.rule][input.dataset.key]=input.dataset.switch?Number(input.checked):input.dataset.array?input.value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean):Number(input.value));
    return result;
  }
  async function refresh() {
    state=await api(base+'state');editable=Boolean((state.browser_access||{}).allow_updates);profile=structuredCopy(state.pending?state.pending.profile:(state.applied||state.default_profile));drawForm();await history();
  }
  function drawExceptions() {
    const area=$('exceptions-list');area.replaceChildren();
    for(const item of profile.exceptions) {
      const row=node('p');row.append(node('code',item.request_id+' '),node('span',item.reason+' '));
      const button=node('button','Remove from pending settings');button.type='button';button.onclick=()=>{profile=collect();profile.exceptions=profile.exceptions.filter(e=>e.request_id!==item.request_id);drawExceptions();edited();};row.append(button);area.append(row);
    }
  }
  function impact(result) {
    const area=$('impact-table');area.replaceChildren();
    if(!result || !result.after) return;
    const wrap=node('div',undefined,'filters-table-scroll'), table=node('table'), heading=node('tr');
    ['UTC month','Metric',result.before_label||'Applied on this input',result.after_label||'Proposed on this input'].forEach(t=>heading.append(node('th',t)));table.append(heading);
    const titles={unique:'Unique visitors',visits:'Visits',pages:'Pages',hits:'Hits',bytes:'Response-body bytes'};
    for(const month of Object.keys(result.after).sort().reverse()) for(const [key,title] of Object.entries(titles)) {
      const row=node('tr');[month,title,result.before&&result.before[month]?Number(result.before[month][key]).toLocaleString():'Unavailable',Number(result.after[month][key]).toLocaleString()].forEach(t=>row.append(node('td',t)));table.append(row);
    } wrap.append(table);area.append(wrap);
    if(result.capacity_fallback && Object.keys(result.capacity_fallback).length) area.append(node('p','Input over limits — dependent filters are inactive for: '+Object.keys(result.capacity_fallback).join(', ')+'. Classifier matches for those periods are unavailable.'));
    if(result.coverage) drawCoverage(result.coverage);
  }
  function drawCurrentImpact(){
    if(!state.managed){$('impact-table').replaceChildren();$('match-counts').replaceChildren();return;}
    impact({before:(state.view_totals||{}).original,after:state.totals,before_label:'Additional filters off',after_label:'Current applied profile',capacity_fallback:state.capacity_fallback});
    const area=$('match-counts');area.replaceChildren(node('h3','Matches and actual exclusions for this generation'));
    const counts=state.matched_requests||{},table=node('table'),header=node('tr');header.append(node('th','Detector / measure'),node('th','Requests'));table.append(header);
    const measures=catalogue.components.filter(item=>item.count_key).map(item=>[item.count_key,item.label]);
    measures.push(['flagged_requests','Individually flagged union'],['overlap_requests','Matched by multiple rules']);
    for(const [key,title] of measures){const row=node('tr');row.append(node('td',title),node('td',counts[key]===undefined?'Unavailable on this generation':Number(counts[key]).toLocaleString()));table.append(row);}area.append(table);
    const views=state.view_totals||{};
    for(const [mode,title,ledger] of [['requests','Matched-request filtering',state.request_excluded_by_month||{}],['behavior','Configured visitor policy',state.excluded_by_month||{}]]){
      for(const month of Object.keys(ledger).sort().reverse()){
        if(!views.confirmed||!views[mode]||!views.confirmed[month]||!views[mode][month])continue;
        const native=ledger[month],removed=native.records,viewed=views.confirmed[month].hits-views[mode][month].hits;
        let detail='Native breakdown unavailable on this generation.';
        if(native.native_nonviewed_records!==undefined&&native.native_dropped_records!==undefined){
          detail='Native replay of the omitted records: '+Number(native.native_viewed_records).toLocaleString()+' viewed; '+Number(native.native_nonviewed_records).toLocaleString()+' non-viewed; '+Number(native.native_dropped_records).toLocaleString()+' ignored by AWStats.';
        }
        area.append(node('p',month+' — '+title+': '+Number(removed).toLocaleString()+' omitted log records; '+Number(viewed).toLocaleString()+' fewer viewed hits. '+detail));
      }
    }
    for(const [key,impact] of Object.entries(state.evidence_classes||{})) {
      for(const [month,value] of Object.entries(impact.by_month||{})) {
        const native=value.native_class||{},exclusive=value.native_exclusive||{};
        area.append(node('p',month+' / '+(names[key]||[key])[0]+': '+value.matched_requests+' matched; '+value.exclusive_requests+' exclusive; '+value.overlapping_requests+' overlapping removals. Native matching requests: '+(native.hits||0)+' viewed hits, '+(native.nonviewed_hits||0)+' non-viewed. Exclusive contribution: '+(exclusive.pages||0)+' pages, '+(exclusive.hits||0)+' viewed hits.'+(key==='historical_operator'?' Applies only to the optional inferred report.':'')));
      }
    }
    area.append(node('p','Per-filter match counts overlap. They cover successfully classified input only. Missing classification results are unavailable. Native user-agent and verified-crawler attribution is reported by native AWStats; no per-rule count is inferred here.','filters-muted'));
  }
  function drawJob(job) {
    $('job-status').replaceChildren(node('p',job.status+' — '+(job.phase||'')));
    if(job.error) $('job-status').append(node('p',job.error));
    if(job.result) {impact(job.result);if(job.result.coverage_required) drawCoverage(job.result.coverage_required);}
    if(editable && ['Completed','Failed'].includes(job.status)) {
      const button=node('button',job.status==='Failed'?'Retry as a new action':'Reprocess as a new action');button.onclick=()=>submitJob(job.action);$('job-status').append(button);
    }
  }
  function drawJobs(jobs) {
    const area=$('recent-jobs');area.replaceChildren();
    jobs.forEach(job=>{const p=node('p',job.created_utc+' · '+job.action+' · '+job.status+' · '+job.actor);area.append(p);});
    const active=jobs.find(j=>['Queued','Running'].includes(j.status));if(active&&!poll) watch(active.id);
  }
  async function watch(id) {
    busy=true;authorization();
    const step=async()=>{
      try {const job=await api('/vstats-control/jobs/'+id);drawJob(job);
        if(['Queued','Running'].includes(job.status)) {poll=setTimeout(step,2500);return;}
        poll=null;busy=false;authorization();
        if(job.status==='Completed'&&job.action==='apply') {message('Reports and applied settings were published together. Reload the report to see this generation.');await refresh();}
        await history();
      } catch(e) {poll=null;busy=false;authorization();message(e.message+' The job is not restarted by this page.');}
    }; await step();
  }
  async function submitJob(action) {
    if(historical || !editable) return;
    if(busy) return;
    if(action==='apply'&&!confirm('Reprocess all retained logs and publish the selected settings? Existing reports stay available until the validated rebuild completes.')) return;
    const id=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');
    const body={profile:collect(),generation:state.generation,action_id:id,coverage_ack:coverage&&$('acknowledge-coverage').checked?coverage.acknowledgement:null};
    busy=true;authorization();
    try {const job=await api(base+action,body);message(action==='preview'?'Preview queued. It will not change published reports.':'Rebuild queued. Reports remain available.');await watch(job.id);} catch(e) {busy=false;authorization();message(e.message);}
  }
  async function settingAction(action,extra={}) {
    if(historical || !editable) return;
    try {const body=Object.assign({generation:state.generation,profile:collect()},extra);await api(base+action,body);await refresh();message(action==='discard'?'Pending edits discarded.':'Changes are pending; published reports have not changed.');}catch(e){message(e.message);}
  }
  function drawLinks() {
    const reviews=$('review-links');reviews.replaceChildren();
    for(const [path,title] of [['review/index.html','Excluded and retained requests'],['classification/index.html','Classification evidence']]) {
      if(!state.managed) continue;const button=node('button',title);button.onclick=()=>{$('review-frame').src=path;$('review-frame').hidden=false;};reviews.append(button);
    }
    const comparisons=$('comparison-links');comparisons.replaceChildren();
    const months=Object.keys(state.totals||{}).sort();if(!months.length||!state.managed)return;
    const selected=context(),month=selected.month;
    const comparisonViews=[['requests','IP expansion off'],['confirmed','Native rules + selected verified-crawler evidence'],['original','All additional filters off']];
    if((state.view_totals||{}).retrospective) comparisonViews.push(['retrospective','Inferred/aggressive comparison (unverified)']);
    for(const [folder,title] of comparisonViews) {
      const button=node('button',title);button.onclick=()=>{$('comparison-frame').src='../'+folder+'/'+month+'/'+selected.filename;$('comparison-frame').hidden=false;};comparisons.append(button);
    }
  }
  async function history() {
    if(!csrf) {$('history-list').textContent='Processing history is available through the browser controls service.';return;}
    try {const entries=await api(base+'history');const area=$('history-list');area.replaceChildren();
      entries.forEach(item=>{const row=node('p',item.time+' · '+item.actor+' · '+(item.profile_id?item.profile_id.slice(0,12):'Unverified profile')+' ');
        if(item.report_url){const link=node('a','Inspect retained reports');link.href=item.report_url;row.append(link,document.createTextNode(' '));}
        if(editable&&item.verified_profile&&!item.current){const button=node('button','Restore settings as pending');button.onclick=()=>settingAction('restore',{restore_generation:item.generation});row.append(button);}area.append(row);});
    }catch(e){message(e.message);}
  }
  $('save-settings').onclick=()=>settingAction('save');$('discard-settings').onclick=()=>settingAction('discard');$('reset-settings').onclick=()=>settingAction('reset');$('preview').onclick=()=>submitJob('preview');$('apply').onclick=()=>submitJob('apply');$('apply-settings').onclick=()=>submitJob('apply');
  $('acknowledge-coverage').onchange=authorization;$('ip-policy').onchange=edited;$('native-level').onchange=edited;
  $('add-exception').onclick=()=>{const id=$('exception-id').value.trim(),reason=$('exception-reason').value.trim();if(!/^[a-f0-9]{64}$/.test(id)||!reason){message('Enter a complete request ID and a reason.');return;}profile=collect();if(profile.exceptions.some(x=>x.request_id===id)){message('This request ID already has an inclusion.');return;}profile.exceptions.push({request_id:id,reason});$('exception-id').value='';$('exception-reason').value='';drawExceptions();edited();message('Inclusion added to unsaved settings. Save or preview it, then Apply & reprocess to change reports.');};
  const returning=new URLSearchParams(location.search).get('return');
  if(returning&&returning.startsWith('/vstats/'+site+'/')&&!returning.startsWith('//')&&!returning.includes('\\'))$('return-report').href=returning;
  function tab(){const value=location.hash||'#settings';document.querySelectorAll('.filters-tabs a').forEach(a=>a.setAttribute('aria-current',String(a.hash===value)));}window.addEventListener('hashchange',tab);
  drawForm();tab();if(historical){$('readonly-note').textContent='Historical snapshot — read-only. Open the current Filters page to change settings.';}else{(async()=>{try{const session=await api('/vstats-control/session');csrf=session.csrf;await refresh();if(!editable)$('readonly-note').textContent='Browser changes and reprocessing are disabled: AllowToUpdateStatsFromBrowser=0.';}catch(error){editable=false;authorization();message(error.message);}})();}
})();
