/* Optional static-publisher control UI. Credentials stay in page memory only. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let state = JSON.parse($('filters-state').textContent);
  let profile = structuredCopy(state.applied || state.default_profile);
  let auth = null, csrf = null, busy = false, poll = null, coverage = state.coverage;
  const site = state.site, base = '/vstats-control/sites/' + encodeURIComponent(site) + '/';
  const historical = $('filters-main').dataset.historical === 'true';
  const rules = ['behavior', 'probing', 'rapid_scan', 'distributed_login'];
  const names = {native_crawlers:['Native crawler signatures','Existing AWStats user-agent detection.'],verified_crawlers:['Verified crawlers','Only dated provider evidence can add this treatment.'],behavior:['Broad probing','Repeated diverse requests and missing paths within a configured time window.'],probing:['Endpoint probing','Requires your explicit endpoint paths; no paths are guessed.'],rapid_scan:['Rapid content-path scanning','Rapid requests across many paths, including missing resources.'],distributed_login:['Distributed login probing','Requires configured login paths and coordinated evidence across sources.']};
  function structuredCopy(v) { return JSON.parse(JSON.stringify(v)); }
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
    if(location.protocol !== 'https:') throw new Error('Open Filters over HTTPS before signing in or making changes.');
    const headers = {'Authorization':auth};
    if(body !== undefined) { headers['Content-Type']='application/json'; headers['X-VStats-CSRF']=csrf; }
    const response = await fetch(path, {method:body===undefined?'GET':'POST', headers, body:body===undefined?undefined:JSON.stringify(body),cache:'no-store',credentials:'omit'});
    const result = await response.json(); if(!response.ok) throw new Error(result.error || 'Request failed'); return result;
  }
  function authorization() {
    const enabled = Boolean(auth && csrf && !busy);
    $('profile-fields').disabled = !enabled; $('exception-fields').disabled = !enabled;
    for(const id of ['save-settings','discard-settings','reset-settings','preview','apply']) $(id).disabled = !enabled;
    $('readonly-note').hidden = Boolean(auth);
    if(coverage && coverage.needs_acknowledgement && !$('acknowledge-coverage').checked) $('apply').disabled = true;
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
  function drawForm() {
    $('site-label').textContent=site; $('applied-description').textContent=(state.applied?'Applied profile '+state.profile_id.slice(0,12):'Legacy/unverified profile; Filters have not been applied.')+' · Report generation '+state.generation+' · '+state.generated_utc;
    $('profile-status').textContent=state.pending?'Pending settings':state.applied?'Applied settings':'Defaults pending';$('profile-note').textContent=state.note||'';
    const list=$('filter-list');list.replaceChildren();
    for(const [key,labels] of Object.entries(names)) {
      const label=node('label',undefined,'filters-option'), checkbox=node('input');checkbox.type='checkbox';checkbox.checked=profile.filters[key];checkbox.dataset.filter=key;checkbox.addEventListener('change',edited);
      const content=node('span');content.append(node('strong',labels[0]),node('small',labels[1]));
      label.append(checkbox,content,node('span',(state.effective||{})[key] || 'Not applied', 'filter-effective'));list.append(label);
    }
    $('ip-policy').checked=profile.exclude_automated_ips; $('native-level').value=profile.native_level;
    const advanced=$('advanced-fields');advanced.replaceChildren();
    for(const rule of rules) {
      const box=node('section');box.append(node('h3',names[rule][0]));const grid=node('div',undefined,'filters-advanced-grid');
      for(const [key,value] of Object.entries(profile.classifier[rule])) {
        if(key==='enabled') continue;
        const label=node('label',key.replace(/_/g,' '));const input=node(Array.isArray(value)?'textarea':'input');input.dataset.rule=rule;input.dataset.key=key;
        if(Array.isArray(value)) {input.value=value.join('\n');input.dataset.array='true';} else {input.type='number';input.step='1';input.min='0';input.value=value;}
        input.addEventListener('input',edited);label.append(input);grid.append(label);
      } box.append(grid);advanced.append(box);
    }
    const periods=$('period-status');periods.replaceChildren();const table=node('table'),heading=node('tr');heading.append(node('th','UTC month'));Object.values(names).forEach(n=>heading.append(node('th',n[0])));table.append(heading);for(const month of Object.keys(state.effective_by_month||{}).sort().reverse()){const row=node('tr');row.append(node('td',month));Object.keys(names).forEach(key=>row.append(node('td',state.effective_by_month[month][key])));table.append(row);}periods.append(table);
    drawExceptions();drawCoverage(state.coverage);authorization();drawLinks();drawJobs(state.jobs||[]);drawCurrentImpact();
  }
  function collect() {
    const result=structuredCopy(profile);
    document.querySelectorAll('[data-filter]').forEach(input=>result.filters[input.dataset.filter]=input.checked);
    result.exclude_automated_ips=$('ip-policy').checked;result.native_level=Number($('native-level').value);
    document.querySelectorAll('[data-rule]').forEach(input=>result.classifier[input.dataset.rule][input.dataset.key]=input.dataset.array?input.value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean):Number(input.value));
    return result;
  }
  async function refresh() {
    state=await api(base+'state');profile=structuredCopy(state.pending?state.pending.profile:(state.applied||state.default_profile));drawForm();await history();
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
    for(const [key,title] of [['broad_flagged_requests','Broad probing'],['probing_flagged_requests','Endpoint probing'],['rapid_scan_flagged_requests','Rapid content-path scanning'],['distributed_login_flagged_requests','Distributed login probing'],['flagged_requests','Individually flagged union'],['overlap_requests','Matched by multiple rules']]){const row=node('tr');row.append(node('td',title),node('td',counts[key]===undefined?'Unavailable on this generation':Number(counts[key]).toLocaleString()));table.append(row);}area.append(table);
    const requested=state.request_excluded_by_month||{},views=state.view_totals||{};
    for(const month of Object.keys(requested).sort().reverse()){
      if(!views.confirmed||!views.requests||!views.confirmed[month]||!views.requests[month])continue;
      const removed=requested[month].records,viewed=views.confirmed[month].hits-views.requests[month].hits;
      area.append(node('p',month+': '+Number(removed).toLocaleString()+' deduplicated matched-request exclusions; '+Number(removed-viewed).toLocaleString()+' of those requests were already non-viewed by the chosen native/verified rules.'));
    }
    area.append(node('p','Per-filter match counts overlap. They cover successfully classified input only. Missing classification results are unavailable. Native user-agent and verified-crawler attribution is reported by native AWStats; no per-rule count is inferred here.','filters-muted'));
  }
  function drawJob(job) {
    $('job-status').replaceChildren(node('p',job.status+' — '+(job.phase||'')));
    if(job.error) $('job-status').append(node('p',job.error));
    if(job.result) {impact(job.result);if(job.result.coverage_required) drawCoverage(job.result.coverage_required);}
    if(['Completed','Failed'].includes(job.status)) {
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
    if(historical) return;
    if(busy) return;
    if(action==='apply'&&!confirm('Reprocess all retained logs and publish the selected settings? Existing reports stay available until the validated rebuild completes.')) return;
    const id=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');
    const body={profile:collect(),generation:state.generation,action_id:id,coverage_ack:coverage&&$('acknowledge-coverage').checked?coverage.acknowledgement:null};
    busy=true;authorization();
    try {const job=await api(base+action,body);message(action==='preview'?'Preview queued. It will not change published reports.':'Rebuild queued. Reports remain available.');await watch(job.id);} catch(e) {busy=false;authorization();message(e.message);}
  }
  async function settingAction(action,extra={}) {
    if(historical) return;
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
    for(const [folder,title] of [['requests','IP expansion off'],['confirmed','Behavioral and IP exclusions off'],['original','All additional filters off']]) {
      const button=node('button',title);button.onclick=()=>{$('comparison-frame').src='../'+folder+'/'+month+'/'+selected.filename;$('comparison-frame').hidden=false;};comparisons.append(button);
    }
  }
  async function history() {
    if(!auth) {$('history-list').textContent='Sign in to inspect processing history or restore previous settings.';return;}
    try {const entries=await api(base+'history');const area=$('history-list');area.replaceChildren();
      entries.forEach(item=>{const row=node('p',item.time+' · '+item.actor+' · '+(item.profile_id?item.profile_id.slice(0,12):'Unverified profile')+' ');
        if(item.report_url){const link=node('a','Inspect retained reports');link.href=item.report_url;row.append(link,document.createTextNode(' '));}
        if(item.verified_profile&&!item.current){const button=node('button','Restore settings as pending');button.onclick=()=>settingAction('restore',{restore_generation:item.generation});row.append(button);}area.append(row);});
    }catch(e){message(e.message);}
  }
  $('login-form').onsubmit=async e=>{e.preventDefault();if(historical)return;auth='Basic '+btoa(unescape(encodeURIComponent($('login-user').value+':'+$('login-password').value)));$('login-password').value='';try{const session=await api('/vstats-control/session');csrf=session.csrf;await refresh();$('admin-login').open=false;message('Signed in as '+session.actor+'. Changes stay pending until Apply & reprocess.');}catch(error){auth=null;csrf=null;authorization();message(error.message);}};
  $('save-settings').onclick=()=>settingAction('save');$('discard-settings').onclick=()=>settingAction('discard');$('reset-settings').onclick=()=>settingAction('reset');$('preview').onclick=()=>submitJob('preview');$('apply').onclick=()=>submitJob('apply');
  $('acknowledge-coverage').onchange=authorization;$('ip-policy').onchange=edited;$('native-level').onchange=edited;
  $('add-exception').onclick=()=>{const id=$('exception-id').value.trim(),reason=$('exception-reason').value.trim();if(!/^[a-f0-9]{64}$/.test(id)||!reason){message('Enter a complete request ID and a reason.');return;}profile=collect();if(profile.exceptions.some(x=>x.request_id===id)){message('This request ID already has an inclusion.');return;}profile.exceptions.push({request_id:id,reason});$('exception-id').value='';$('exception-reason').value='';drawExceptions();edited();message('Inclusion added to unsaved settings. Save or preview it, then Apply & reprocess to change reports.');};
  const returning=new URLSearchParams(location.search).get('return');
  if(returning&&returning.startsWith('/vstats/'+site+'/')&&!returning.startsWith('//')&&!returning.includes('\\'))$('return-report').href=returning;
  function tab(){const value=location.hash||'#settings';document.querySelectorAll('.filters-tabs a').forEach(a=>a.setAttribute('aria-current',String(a.hash===value)));}window.addEventListener('hashchange',tab);
  drawForm();tab();if(historical){$('admin-login').hidden=true;$('readonly-note').textContent='Historical snapshot — read-only. Open the current Filters page to change settings.';}
})();
