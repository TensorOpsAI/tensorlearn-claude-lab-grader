"""Fixed-rule grading for standalone starters: no AI report and no model judgment.

Documents are read as data on the host. Candidate code runs only in the offline,
credential-free Docker worker, each call in its own child process. The host keeps
every expectation and compares the raw observations.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
from bug_assessment import CandidateFailure, Unavailable, IMAGE, bounded, clean_env, decode_results

# One fixed harness. Jobs come from the host; each runs in a child node process, so
# candidate output can never be confused with the harness result line.
HARNESS = r'''import fs from 'node:fs';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
const jobs=JSON.parse(fs.readFileSync('/trusted/jobs.json','utf8'));
const env={PATH:'/usr/local/bin:/usr/bin:/bin',HOME:'/tmp',NODE_OPTIONS:''};
const hash=p=>{try{return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');}catch{return null;}};
const hooksFixture=()=>{
 for(const name of fs.readdirSync('/workspace'))fs.rmSync('/workspace/'+name,{recursive:true,force:true});
 fs.mkdirSync('/workspace/src',{recursive:true});fs.mkdirSync('/workspace/tests/instructor',{recursive:true});
 fs.writeFileSync('/workspace/intent.md','approved');fs.writeFileSync('/workspace/tests/instructor/check.mjs','protected');
 fs.writeFileSync('/workspace/src/app.mjs','old');fs.symlinkSync('/workspace/intent.md','/workspace/src/shortcut');
};
const fixtureHashes=()=>[hash('/workspace/intent.md'),hash('/workspace/tests/instructor/check.mjs'),hash('/workspace/src/app.mjs')].join(',');
const results=[];
for(const job of jobs){
 let cwd='/workspace',before=null;
 if(job.fixture==='hooks'){hooksFixture();before=fixtureHashes();}
 if(job.copy){
  fs.rmSync('/tmp/run',{recursive:true,force:true});fs.cpSync('/candidate','/tmp/run',{recursive:true});
  for(const [name,text] of Object.entries(job.copy.replace||{}))fs.writeFileSync('/tmp/run/'+name,text);
  cwd='/tmp/run';
 }
 const child=spawnSync(process.execPath,job.argv,{cwd,env,input:job.input??'',encoding:'utf8',timeout:job.timeout??5000,maxBuffer:65536});
 const out=(child.stdout||'').trim().split('\n').pop()||'';
 results.push({status:child.error?null:child.status,out:out.length<=2000?out:'',mutated:before!==null&&before!==fixtureHashes()});
}
process.stdout.write(JSON.stringify(results));
'''

def run_jobs(workspace,image,jobs,timeout=90):
    """Run fixed jobs against a read-only copy of the candidate files."""
    if not isinstance(image,str) or not IMAGE.fullmatch(image): raise Unavailable('A digest-pinned worker image is required')
    try: available=subprocess.run(['docker','image','inspect',image],env=clean_env(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
    except (OSError,subprocess.TimeoutExpired) as error: raise Unavailable('Docker is unavailable') from error
    if available.returncode: raise Unavailable('Pinned worker image must be preloaded')
    with tempfile.TemporaryDirectory(prefix='tensorlearn-fixed-rules-') as folder:
        trusted=Path(folder)/'trusted'; trusted.mkdir()
        (trusted/'harness.mjs').write_text(HARNESS); (trusted/'jobs.json').write_text(json.dumps(jobs))
        for path in (trusted,*trusted.iterdir()): path.chmod(0o755 if path.is_dir() else 0o644)
        name='tensorlearn-fixed-'+secrets.token_hex(8)
        command=['docker','run','--rm','--pull=never','--name',name,'--network=none','--read-only',
            '--cap-drop=ALL','--security-opt=no-new-privileges','--user=65534:65534',
            '--pids-limit=64','--memory=256m','--cpus=1','--ulimit=nofile=128:128',
            '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m',
            '--tmpfs=/workspace:rw,nosuid,nodev,noexec,size=4m,mode=1777','--workdir=/workspace',
            '--mount',f'type=bind,src={Path(workspace).resolve()},dst=/candidate,readonly',
            '--mount',f'type=bind,src={trusted},dst=/trusted,readonly',
            '--env=HOME=/tmp','--env=NODE_OPTIONS=','--entrypoint=node',image,'/trusted/harness.mjs']
        try:
            code,out,_=bounded(command,timeout)
            if code==125: raise Unavailable('Docker could not create the isolated worker')
            observed=decode_results(out) if code==0 else None
            if not isinstance(observed,list) or len(observed)!=len(jobs): raise CandidateFailure('Worker returned malformed evidence')
            return observed
        finally:
            subprocess.run(['docker','rm','-f',name],env=clean_env(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)

def call(module,expression,input_value=None,**extra):
    """A job that imports one candidate module and prints one JSON value."""
    script=(f"import fs from 'node:fs';import * as m from 'file:///candidate/{module}';"
            "const input=JSON.parse(fs.readFileSync(0,'utf8')||'null');"
            f"const value=await (async()=>{{{expression}}})();console.log(JSON.stringify(value));")
    return {'argv':['--input-type=module','-e',script],'input':json.dumps(input_value),**extra}

def parsed(result):
    try: return json.loads(result['out']) if result['status']==0 else None
    except ValueError: return None

def text(workspace,relative,limit=65536):
    path=Path(workspace)/relative
    if path.is_symlink() or not path.is_file() or path.stat().st_size>limit: return ''
    try: return path.read_text(encoding='utf-8')
    except UnicodeError: return ''

def sections(markdown,heading='##'):
    """Map each heading to its body text (code blocks included)."""
    found={}
    for match in re.finditer(rf'^{heading} +(.+?)\s*\n(.*?)(?=^{heading} |\Z)',markdown,re.M|re.S):
        found[match.group(1).strip().lower()]=match.group(2).strip()
    return found

# hooks ------------------------------------------------------------------------

def edit(path,cwd='/workspace'): return {'tool_name':'Edit','tool_input':{'file_path':path,'old_string':'old','new_string':'new'},'cwd':cwd}
def write(path,cwd='/workspace'): return {'tool_name':'Write','tool_input':{'file_path':path,'content':'changed'},'cwd':cwd}
def bash(command): return {'tool_name':'Bash','tool_input':{'command':command},'cwd':'/workspace'}

# Grouped by the published contract. Only the documented probe vocabulary is used.
HOOK_GROUPS={
 'direct-path':('Direct writes to protected files are denied',[
   (write('/workspace/intent.md'),'deny'),(edit('/workspace/intent.md'),'deny'),
   (write('/workspace/tests/instructor/check.mjs'),'deny'),(edit('/workspace/tests/instructor/sub/x.mjs'),'deny')]),
 'normalization':('Relative, dotted and doubled paths resolve to the same protected target',[
   (edit('/workspace/src/../intent.md'),'deny'),(edit('intent.md'),'deny'),(edit('./intent.md'),'deny'),
   (edit('../intent.md','/workspace/src'),'deny'),(write('/workspace/src/../tests/instructor/check.mjs'),'deny'),
   (edit('/workspace//intent.md'),'deny'),(edit('/workspace/src/./app.mjs'),'allow'),(edit('/workspace/src/../src/app.mjs'),'allow')]),
 'symlink':('A symlink to a protected file is treated as that file',[
   (write('/workspace/src/shortcut'),'deny'),(edit('src/shortcut'),'deny'),(bash('printf x > src/shortcut'),'deny')]),
 'shell-routes':('Shell redirects, cp, mv, tee and python writes to protected files are denied',[
   (bash('printf changed > intent.md'),'deny'),(bash('printf changed >> intent.md'),'deny'),(bash('echo x > ./intent.md'),'deny'),
   (bash('printf x > /workspace/intent.md'),'deny'),(bash('printf x > tests/instructor/check.mjs'),'deny'),
   (bash('cp src/app.mjs intent.md'),'deny'),(bash('mv src/app.mjs intent.md'),'deny'),(bash('mv intent.md src/old.md'),'deny'),
   (bash('printf x | tee intent.md'),'deny'),(bash('printf x | tee -a tests/instructor/check.mjs'),'deny'),
   (bash('python3 -c "open(\'intent.md\',\'w\').write(\'x\')"'),'deny')]),
 'allow-source':('Ordinary source edits are allowed',[
   (edit('/workspace/src/app.mjs'),'allow'),(write('/workspace/src/new.mjs'),'allow'),(bash('printf new > src/app.mjs'),'allow')]),
 'allow-read':('Read-only commands are allowed',[(bash('cat intent.md'),'allow'),(bash('cat tests/instructor/check.mjs'),'allow')]),
 'lookalike-paths':('Look-alike names under src/ are not mistaken for protected files',[
   (write('/workspace/src/intent.md'),'allow'),(write('/workspace/src/tests/instructor/x.mjs'),'allow'),(write('/workspace/src/notintent.md'),'allow')]),
 'invalid-input':('Malformed events are denied without crashing',[
   (None,'deny'),({},'deny'),({'tool_name':'Write','tool_input':{},'cwd':'/workspace'},'deny'),
   ({'tool_name':'Write','tool_input':{'file_path':42},'cwd':'/workspace'},'deny'),({'tool_name':'Bash','tool_input':{},'cwd':'/workspace'},'deny')]),
}
HOOK_CRITICAL=[write('/workspace/intent.md'),bash('printf changed > intent.md'),write('/workspace/src/shortcut'),write('/workspace/tests/instructor/check.mjs')]
STARTER_GUARD="export function decide(){return {hookSpecificOutput:{hookEventName:'PreToolUse',permissionDecision:'allow',permissionDecisionReason:'starter'}};}\n"

def decision(result):
    value=parsed(result)
    output=value.get('hookSpecificOutput') if isinstance(value,dict) and set(value)=={'hookSpecificOutput'} else None
    if (not isinstance(output,dict) or set(output)!={'hookEventName','permissionDecision','permissionDecisionReason'}
        or output['hookEventName']!='PreToolUse' or output['permissionDecision'] not in ('allow','deny')
        or not isinstance(output['permissionDecisionReason'],str) or not 0<len(output['permissionDecisionReason'])<=2000):
        return None
    return output['permissionDecision']

def hooks(workspace,image):
    decide="if(typeof m.decide!=='function')throw 0;const r=m.decide(input);if(r&&typeof r.then==='function')throw 0;return r;"
    cases=[(group,event,expected) for group,(_,rows) in HOOK_GROUPS.items() for event,expected in rows]
    jobs=[call('guard/guard.mjs',decide,event,fixture='hooks') for _,event,_ in cases]
    student=['--test','tests/student/guard/**/*.test.mjs']
    jobs+=[{'argv':student,'copy':{},'timeout':20000},{'argv':student,'copy':{'replace':{'guard/guard.mjs':STARTER_GUARD}},'timeout':20000}]
    observed=run_jobs(workspace,image,jobs)
    decisions=[decision(r) for r in observed[:len(cases)]]
    checks=[]
    for group,(label,_) in HOOK_GROUPS.items():
        rows=[i for i,c in enumerate(cases) if c[0]==group]
        checks.append({'id':group,'passed':all(decisions[i]==cases[i][2] and not observed[i]['mutated'] for i in rows)})
    checks.append({'id':'event-contract','passed':all(d is not None for d in decisions)})
    checks.append({'id':'no-side-effects','passed':not any(r['mutated'] for r in observed[:len(cases)])})
    tested,starter=observed[len(cases):]
    checks.append({'id':'student-tests-pass','passed':tested['status']==0})
    checks.append({'id':'student-tests-catch-allow-all','passed':tested['status']==0 and starter['status'] not in (0,None)})
    critical=[i for i,c in enumerate(cases) if c[1] in HOOK_CRITICAL]
    allow_all=all(d=='allow' for d in decisions) or all(d=='deny' for d in decisions)
    capped=allow_all or any(decisions[i]!='deny' for i in critical)
    return checks,capped

# recurring-regressions --------------------------------------------------------

FALSE_CONVENTIONS=['Customer references use the `CUST-1234` format','Normalize new routes and helpers to this format','every request must call claims-core directly',
                   'Remove local caching','that is the complete project validation command']
USEFUL_GUIDANCE=['es modules','node 22','install dependencies','owner authorization','log patient or claim payloads','new recipients','clinical details']
OLD_FORMAT="export function normalizeCustomerCode(value){if(typeof value!=='string')throw new TypeError('text');const code=value.trim().toUpperCase();if(!/^CUST-[0-9]{4}$/.test(code))throw new TypeError('invalid');return code;}\n"
NO_CACHE="import {normalizeCustomerCode} from './customer-code.mjs';\nexport function createClaimsClient(fetchClaim){return {async get(code){return fetchClaim(normalizeCustomerCode(code));}};}\n"
NORMALIZE_OK=[(' cus-000123 ','CUS-000123'),('CUS-000009','CUS-000009'),('cus-890001','CUS-890001'),('CUS-000000','CUS-000000'),('\tcus-000123\n','CUS-000123')]
NORMALIZE_BAD=['CUST-1234','CUS-12345','CUS-1234567','CUS-0000ab','','   ',None,123,{}]
CACHE_SCRIPT=r'''const {createClaimsClient}=await import('file:///candidate/src/claims-client.mjs');
const run=async(steps,options)=>{let time=0,calls=[];const client=createClaimsClient(async code=>{calls.push(code);if(steps.fail&&calls.length===1)throw new Error('down');return {code};},{now:()=>time,...options});
 const seen=[];for(const [at,code] of steps.gets){time=at;try{await client.get(code);seen.push('ok');}catch(e){seen.push(e instanceof TypeError?'type':'error');}}return {calls,seen};};
return {
 ttl:await run({gets:[[0,'CUS-000123'],[29999,'CUS-000123'],[30000,'CUS-000123']]}),
 shared:await run({gets:[[0,' cus-000123 '],[1,'CUS-000123']]}),
 independent:await run({gets:[[0,'CUS-000123'],[1,'CUS-000124']]}),
 custom:await run({gets:[[0,'CUS-000123'],[999,'CUS-000123'],[1000,'CUS-000123']]},{ttlMs:1000}),
 failure:await run({fail:true,gets:[[0,'CUS-000123'],[1,'CUS-000123']]}),
 invalid:await run({gets:[[0,'CUST-1234']]}),
};'''
CACHE_EXPECTED={
 'ttl':{'calls':['CUS-000123','CUS-000123'],'seen':['ok','ok','ok']},
 'shared':{'calls':['CUS-000123'],'seen':['ok','ok']},
 'independent':{'calls':['CUS-000123','CUS-000124'],'seen':['ok','ok']},
 'custom':{'calls':['CUS-000123','CUS-000123'],'seen':['ok','ok','ok']},
 'failure':{'calls':['CUS-000123','CUS-000123'],'seen':['error','ok']},
 'invalid':{'calls':[],'seen':['type']},
}

def recurring(workspace,image):
    normalize="try{return {value:m.normalizeCustomerCode(input)};}catch(e){return {error:e instanceof TypeError?'type':'other'};}"
    jobs=[call('src/customer-code.mjs',normalize,value) for value,_ in NORMALIZE_OK]
    jobs+=[call('src/customer-code.mjs',normalize,value) for value in NORMALIZE_BAD]
    jobs.append(call('src/claims-client.mjs',CACHE_SCRIPT))
    suite=['--test','tests/*.test.mjs','tests/student/**/*.test.mjs']
    student=['--test','tests/student/**/*.test.mjs']
    jobs+=[{'argv':suite,'copy':{},'timeout':20000},{'argv':student,'copy':{},'timeout':20000},
           {'argv':student,'copy':{'replace':{'src/customer-code.mjs':OLD_FORMAT}},'timeout':20000},
           {'argv':student,'copy':{'replace':{'src/claims-client.mjs':NO_CACHE}},'timeout':20000}]
    observed=run_jobs(workspace,image,jobs)
    ok,bad=len(NORMALIZE_OK),len(NORMALIZE_BAD)
    cache=parsed(observed[ok+bad]) or {}
    suite_run,student_run,old_format,no_cache=observed[ok+bad+1:]
    caught=lambda r: student_run['status']==0 and r['status'] not in (0,None)
    checks=[
     {'id':'normalize-current-format','passed':all(parsed(observed[i])=={'value':want} for i,(_,want) in enumerate(NORMALIZE_OK))},
     {'id':'normalize-rejects-old-and-malformed','passed':all(parsed(observed[ok+i])=={'error':'type'} for i in range(bad))},
     {'id':'cache-thirty-second-boundary','passed':cache.get('ttl')==CACHE_EXPECTED['ttl'] and cache.get('custom')==CACHE_EXPECTED['custom']},
     {'id':'cache-per-normalized-customer','passed':all(cache.get(k)==CACHE_EXPECTED[k] for k in ('shared','independent'))},
     {'id':'cache-skips-failures-and-invalid-codes','passed':all(cache.get(k)==CACHE_EXPECTED[k] for k in ('failure','invalid'))},
     {'id':'full-suite-passes','passed':suite_run['status']==0},
     {'id':'student-tests-catch-old-format','passed':caught(old_format)},
     {'id':'student-tests-catch-missing-cache','passed':caught(no_cache)},
    ]
    documents,false_kept=recurring_documents(workspace)
    return checks+documents,false_kept

def recurring_documents(workspace):
    claude=text(workspace,'CLAUDE.md'); lower=claude.lower()
    diagnosis=sections(text(workspace,'diagnosis.md'))
    false_kept=any(f in claude for f in FALSE_CONVENTIONS)
    checks=[
     {'id':'claude-md-false-conventions-removed','passed':bool(claude) and not false_kept},
     {'id':'claude-md-useful-guidance-kept','passed':sum(g in lower for g in USEFUL_GUIDANCE)>=5},
     # The starter already mentions CUS-123456 as "legacy", so the mention only counts once the false rule is gone.
     {'id':'claude-md-current-customer-code','passed':not false_kept
        and bool(re.search(r'six|6 digits|\{6\}|\\d\{6\}|cus-\d{6}',lower))},
     {'id':'claude-md-cache-and-full-suite','passed':'cach' in lower and bool(re.search(r'\b30\b|30 ?s|30,?000',lower)) and 'tests/student' in lower},
     {'id':'diagnosis-complete','passed':all(len(diagnosis.get(h,''))>=40 for h in ('observed cause','evidence','targeted correction','fresh-session verification'))},
     {'id':'diagnosis-names-the-cause','passed':'claude.md' in diagnosis.get('observed cause','').lower()},
    ]
    return checks,false_kept

# shared document helpers ------------------------------------------------------

def strict_json(data):
    def pairs(items):
        value={}
        for key,item in items:
            if key in value: raise ValueError('Duplicate keys')
            value[key]=item
        return value
    return json.loads(data,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite')))

def json_file(workspace,relative):
    try: return strict_json(text(workspace,relative) or 'null')
    except (ValueError,RecursionError): return None

def json_block(markdown):
    """The single fenced ```json block of a document, or None."""
    blocks=re.findall(r'^```json[ \t]*\n(.*?)^```[ \t]*$',markdown,re.M|re.S)
    if len(blocks)!=1: return None
    try:
        value=strict_json(blocks[0])
        return value if isinstance(value,dict) else None
    except (ValueError,RecursionError): return None

# Words that mark a line as rejecting, excluding or superseding what it mentions.
NEGATION=re.compile(r"\b(not|no|never|without|avoid\w*|skip\w*|exclud\w*|reject\w*|supersed\w*|obsolete|ignor\w*|don't|do not|instead of|rather than)\b|out of scope")

def negated(line):
    """True when the line rejects what it mentions. File names like archived-notes.md don't count."""
    return bool(NEGATION.search(re.sub(r'\barchived-[\w-]+\.md\b','',line.lower())))

def prose(markdown):
    return re.sub(r'^```.*?^```[ \t]*$','',markdown,flags=re.M|re.S)

def written(value,minimum):
    return isinstance(value,str) and len(value.strip())>=minimum and not re.search(r'\bTODO\b|<!--',value)

def as_set(value,vocabulary):
    """A list of distinct strings drawn from the published vocabulary, as a set; else None."""
    if not isinstance(value,list) or not all(isinstance(v,str) for v in value) or len(set(value))!=len(value): return None
    return set(value) if set(value)<=set(vocabulary) else None

# intent -----------------------------------------------------------------------

# Published in the starter README: learners choose values from these vocabularies.
INTENT_VOCABULARY={
 'notifyWhen':['lab-upload-complete','doctor-reviewed','released','result-abnormal'],
 'messageMayInclude':['update-available','test-name','result-value','diagnosis','treatment'],
 'inScope':['existing-portal-route','duplicate-prevention','delivery-failure-handling','portal-redesign',
            'appointment-scheduling','clinical-interpretation','third-party-notifications','patient-dashboard'],
 'openTopics':['channel','referring-doctor-notification','portal-redesign'],
 'owners':['product','privacy','clinical','engineering','support'],
 'successMeasures':['status-only-calls','delivery-failures','all-inbound-calls','clinical-questions'],
}
INTENT_BLOCK='''```json
{
  "notifyWhen": [],
  "messageMayInclude": [],
  "inScope": [],
  "openDecisions": [{"topic": "", "owners": []}],
  "successMeasures": [],
  "numericTarget": null
}
```'''

def intent(workspace,image):
    document=text(workspace,'intent.md'); block=json_block(document) or {}
    words=prose(document).lower(); vocab=INTENT_VOCABULARY
    pick=lambda field,vocabulary: as_set(block.get(field),vocab[vocabulary])
    notify=pick('notifyWhen','notifyWhen'); message=pick('messageMayInclude','messageMayInclude')
    decisions={}
    for item in block.get('openDecisions') if isinstance(block.get('openDecisions'),list) else []:
        if isinstance(item,dict) and set(item)=={'topic','owners'} and item['topic'] in vocab['openTopics']:
            decisions[item['topic']]=as_set(item['owners'],vocab['owners'])
    checks=[
     {'id':'intent-written','passed':written(prose(document),400)},
     {'id':'prose-covers-purpose-scope-success-and-open-decisions','passed':all(w in words for w in ('scope','success','owner')) and bool(re.search(r'out of scope|exclu|not in scope',words))},
     {'id':'decision-record-present','passed':bool(block) and set(block)=={'notifyWhen','messageMayInclude','inScope','openDecisions','successMeasures','numericTarget'}},
     {'id':'review-and-release-gate','passed':notify=={'doctor-reviewed','released'}},
     {'id':'message-without-clinical-detail','passed':message=={'update-available'}},
     {'id':'approved-scope-only','passed':pick('inScope','inScope')=={'existing-portal-route','duplicate-prevention','delivery-failure-handling'}},
     {'id':'channel-open-with-owners','passed':decisions.get('channel')=={'product','privacy'}},
     {'id':'referring-doctor-open-with-owners','passed':decisions.get('referring-doctor-notification')=={'clinical','privacy'}},
     {'id':'no-invented-decisions','passed':set(decisions)=={'channel','referring-doctor-notification'}},
     {'id':'observable-success-measures','passed':pick('successMeasures','successMeasures')=={'status-only-calls','delivery-failures'}},
     {'id':'no-invented-target','passed':'numericTarget' in block and block['numericTarget'] is None},
    ]
    capped=notify is None or not {'doctor-reviewed','released'}<=notify or 'lab-upload-complete' in notify or message!={'update-available'}
    return checks,capped

# review -----------------------------------------------------------------------

SEVERITIES=('critical','major','minor')
FINDING_FIELDS={'path','line','severity','requirement','evidence','recommendation'}
REVIEW_BLOCK='''```json
{
  "fixtures/defective.patch": {"findings": []},
  "fixtures/clean.patch": {"findings": []}
}
```'''

def findings(value):
    """Validate one findings object against findings.schema.json; return the list or None."""
    if not isinstance(value,dict) or set(value)!={'findings'} or not isinstance(value['findings'],list) or len(value['findings'])>10: return None
    for item in value['findings']:
        if (not isinstance(item,dict) or set(item)!=FINDING_FIELDS or type(item['line']) is not int or item['line']<1
            or item['severity'] not in SEVERITIES or not all(isinstance(item[k],str) and item[k].strip() for k in FINDING_FIELDS-{'line'})):
            return None
    return value['findings']

def review(workspace,image):
    policy=text(workspace,'REVIEW.md'); block=json_block(policy) or {}
    reviewer=json_file(workspace,'agents/reviewer.json')
    defective=findings(block.get('fixtures/defective.patch')); clean=findings(block.get('fixtures/clean.patch'))
    path=lambda f: re.sub(r'^[ab]/','',f['path'].strip())  # diff headers say a/ and b/
    status=[f for f in defective or [] if path(f)=='src/status.mjs']
    def found(line,requirements,severities):
        return any(f['line']==line and f['requirement'].strip() in requirements and f['severity'] in severities for f in status)
    nits=[f for f in defective or [] if path(f)=='generated/styles.css']
    # PLAN-1 requires preserving the gate, the cache and log redaction, so it supports all three.
    supported={(2,'SPEC-CACHE'),(3,'SPEC-PRIVACY'),(4,'INTENT-1'),(2,'PLAN-1'),(3,'PLAN-1'),(4,'PLAN-1')}
    checks=[
     {'id':'policy-written','passed':written(prose(policy),300)},
     {'id':'policy-covers-evidence-severity-and-requirements','passed':written(prose(policy),300) and all(w in prose(policy).lower() for w in ('evidence','severity','requirement'))},
     {'id':'reviewer-is-read-only-config','passed':isinstance(reviewer,dict) and set(reviewer)=={'purpose','instructions','output'}
        and reviewer['output']=='findings.schema.json' and written(reviewer.get('instructions'),80)},
     {'id':'findings-match-schema','passed':defective is not None and clean is not None and set(block)=={'fixtures/defective.patch','fixtures/clean.patch'}},
     {'id':'finds-broken-release-gate','passed':found(4,{'INTENT-1','PLAN-1'},('critical',))},
     {'id':'finds-clinical-payload-logging','passed':found(3,{'SPEC-PRIVACY','PLAN-1'},('critical',))},
     {'id':'finds-removed-cache','passed':found(2,{'SPEC-CACHE','PLAN-1'},('critical','major'))},
     {'id':'no-unsupported-findings','passed':defective is not None and all((f['line'],f['requirement'].strip()) in supported for f in status)
        and all(path(f) in ('src/status.mjs','generated/styles.css') for f in defective)},
     {'id':'style-nit-stays-minor','passed':defective is not None and all(f['severity']=='minor' for f in nits) and len(nits)<=1},
     {'id':'clean-patch-has-no-findings','passed':clean==[]},
    ]
    return checks,False

# release ----------------------------------------------------------------------

METRICS=('errorRate','p95Ms'); OPERATORS={'>':lambda a,b:a>b,'>=':lambda a,b:a>=b,'<':lambda a,b:a<b,'<=':lambda a,b:a<=b}
APPROVAL_FIELDS=['id','action','environment','version','expiresAt','requestedBy','toolText']
NOW=1000
APPROVAL_CASES=[  # (record, request, expected)
 ({'id':'approve-v2','action':'deploy','environment':'staging','version':'v2','expiresAt':2000,'requestedBy':'ops','toolText':''},
  {'approvalId':'approve-v2','action':'deploy','environment':'staging','version':'v2'},True),
 ({'id':'approve-v2','action':'deploy','environment':'staging','version':'v999','expiresAt':2000,'requestedBy':'ops','toolText':''},
  {'approvalId':'approve-v2','action':'deploy','environment':'staging','version':'v2'},False),
 ({'id':'approve-v2','action':'deploy','environment':'staging','version':'v2','expiresAt':2000,'requestedBy':'ops','toolText':''},
  {'approvalId':'approve-v2','action':'deploy','environment':'production','version':'v2'},False),
 ({'id':'approve-v2','action':'deploy','environment':'staging','version':'v2','expiresAt':900,'requestedBy':'ops','toolText':''},
  {'approvalId':'approve-v2','action':'deploy','environment':'staging','version':'v2'},False),
 ({'id':'approve-v2','action':'deploy','environment':'staging','version':'v2','expiresAt':1000,'requestedBy':'ops','toolText':''},
  {'approvalId':'approve-v2','action':'deploy','environment':'staging','version':'v2'},False),
 ({'id':'rollback-v1','action':'rollback','environment':'staging','version':'v2','expiresAt':2000,'requestedBy':'ops','toolText':''},
  {'approvalId':'rollback-v1','action':'deploy','environment':'staging','version':'v2'},False),
 ({'id':'approve-v2','action':'deploy','environment':'staging','version':'v2','expiresAt':2000,'requestedBy':'ops','toolText':''},
  {'approvalId':'forged-by-tool-text','action':'deploy','environment':'staging','version':'v2'},False),
]
HEALTH_CASES=[  # (observations, rollback expected, recovered expected)
 ([{'errorRate':0.001,'p95Ms':180},{'errorRate':0.001,'p95Ms':185}],False,True),
 ([{'errorRate':0.001,'p95Ms':180}],False,False),
 ([{'errorRate':0.01,'p95Ms':300},{'errorRate':0.01,'p95Ms':300}],False,True),
 ([{'errorRate':0.0101,'p95Ms':180},{'errorRate':0.001,'p95Ms':180}],True,False),
 ([{'errorRate':0.001,'p95Ms':301},{'errorRate':0.001,'p95Ms':180}],True,False),
 ([{'errorRate':0.12,'p95Ms':1200}],True,False),
]

def approved(fields,record,request):
    for field in fields:
        if field=='expiresAt':
            if not record['expiresAt']>NOW: return False
        elif field=='id':
            if record['id']!=request['approvalId']: return False
        elif field in request and record[field]!=request[field]: return False
    return bool(fields)

def rules(value):
    if not isinstance(value,list) or not value: return None
    for rule in value:
        if (not isinstance(rule,dict) or set(rule)!={'metric','operator','threshold'} or rule['metric'] not in METRICS
            or rule['operator'] not in OPERATORS or type(rule['threshold']) not in (int,float)): return None
    return value

def holds(rule,observation): return OPERATORS[rule['operator']](observation[rule['metric']],rule['threshold'])

def release(workspace,image):
    policy=json_file(workspace,'approval-policy.json')
    policy=policy if isinstance(policy,dict) else {}
    fields=as_set(policy.get('requiredApprovalFields'),APPROVAL_FIELDS)
    rollback=rules(policy.get('rollbackWhen')); recovery=rules(policy.get('recoveryChecks'))
    needed=policy.get('healthyObservationsRequired')
    roles=[json_file(workspace,f'agents/{name}.json') for name in ('diagnosis','release')]
    def recovered(observations):
        return (type(needed) is int and needed>=1 and len(observations)>=needed
                and all(holds(r,o) for o in observations[-needed:] for r in recovery))
    approvals_ok=fields is not None and all(approved(fields,r,q)==want for r,q,want in APPROVAL_CASES)
    checks=[
     {'id':'staging-only-with-approval','passed':policy.get('environment')=='staging' and policy.get('requireApproval') is True},
     {'id':'approval-fields','passed':fields=={'id','action','environment','version','expiresAt'}},
     {'id':'mismatched-or-expired-approvals-denied','passed':approvals_ok},
     {'id':'rollback-triggers','passed':rollback is not None and all(any(holds(r,o) for o in obs for r in rollback)==want for obs,want,_ in HEALTH_CASES)},
     {'id':'recovery-needs-two-healthy-observations','passed':recovery is not None and needed==2 and all(recovered(obs)==want for obs,_,want in HEALTH_CASES)},
     {'id':'failed-rollback-escalates','passed':policy.get('onFailedRollback')=='escalate'},
     {'id':'policy-has-no-extra-authority','passed':set(policy)=={'environment','requireApproval','requiredApprovalFields','rollbackWhen','recoveryChecks','healthyObservationsRequired','onFailedRollback'}},
     {'id':'role-instructions-written','passed':all(isinstance(r,dict) and set(r)=={'purpose','instructions'} and written(r.get('instructions'),100) for r in roles)},
     {'id':'diagnosis-role-is-read-only','passed':isinstance(roles[0],dict) and bool(re.search(r'read[- ]only|do not (deploy|mutate|roll)|never (deploy|mutate)|no mutation',str(roles[0].get('instructions','')),re.I))},
    ]
    capped=not checks[0]['passed'] or not approvals_ok
    return checks,capped

# spec-plan --------------------------------------------------------------------

REAL_PATHS={'src/portal/result-route.mjs','src/service/queue.mjs'}

def table_rows(markdown,header):
    """Rows of the markdown table whose header row starts with the given cells."""
    lines=markdown.splitlines(); rows=[]
    for i,line in enumerate(lines):
        if [c.strip().lower() for c in line.strip().strip('|').split('|')][:len(header)]==header:
            for row in lines[i+2:]:
                if not row.strip().startswith('|'): break
                rows.append([c.strip() for c in row.strip().strip('|').split('|')])
            break
    return rows

def spec_plan(workspace,image):
    spec=text(workspace,'spec.md'); plan=text(workspace,'plan.md'); both=(spec+'\n'+plan); lower=both.lower()
    spec_parts=sections(spec); plan_parts=sections(plan)
    trace=table_rows(spec,['intent','requirement','test']); steps=table_rows(plan,['requirement','step','existing path','test'])
    mentioned=set(re.findall(r'src/[A-Za-z0-9_./-]+\.mjs',both))
    cell=lambda c: c.strip().strip('`*').strip()
    existing={cell(c[2]) for c in steps if len(c)>=4}-{'','-','—','none','n/a','None','N/A'}
    # A path that doesn't exist yet is fine on lines that call it new or reject it (original rubric).
    invented=[p for p in mentioned-REAL_PATHS
              if any(p.lower() in l and not (re.search(r'\bnew\b',l) or negated(l)) for l in lower.splitlines())]
    ordered=re.findall(r'^\s*\d+\.\s+\S',plan_parts.get('ordered steps',''),re.M)
    open_part=spec_parts.get('open decisions and owners','').lower()
    def lines_with(*words): return [l for l in lower.splitlines() if all(w in l for w in words)]
    checks=[
     {'id':'spec-sections-written','passed':all(len(spec_parts.get(h,''))>=40 for h in ('requirements','design','open decisions and owners'))},
     {'id':'plan-sections-written','passed':all(len(plan_parts.get(h,''))>=40 for h in ('ordered steps','paths and dependencies','risks and verification'))},
     {'id':'every-intent-traced','passed':all(any(re.match(rf'I-{n}\b',cell(r[0])) and len(r)>=3 and r[1] and r[2] for r in trace) for n in range(1,5))},
     {'id':'plan-table-complete','passed':len(steps)>=4 and all(len(r)>=4 and r[0] and r[1] and r[3] for r in steps)},
     {'id':'only-real-source-paths','passed':not invented and existing<=REAL_PATHS and REAL_PATHS<=mentioned},
     {'id':'ordered-steps','passed':len(ordered)>=3},
     {'id':'review-and-release-gate','passed':bool(lines_with('review','release'))},
     {'id':'privacy-in-messages-and-logs','passed':bool(lines_with('clinical','log')) and 'portal' in lower},
     {'id':'provider-limits','passed':bool(re.search(r'\b50\b',lower)) and bool(re.search(r'\b20\b',lower)) and bool(lines_with('version')) and 'idempot' in lower},
     {'id':'tests-for-gate-privacy-retry-throughput','passed':all(re.search(p,lower) for p in (r'gat',r'privacy|clinical',r'duplicate|retr',r'throughput|rate|boundar'))},
     {'id':'open-decisions-with-owners','passed':all(w in open_part for w in ('channel','referring','product','privacy','clinical'))},
    ]
    adopted=any(re.search(p,l) and not negated(l)
                for l in lower.splitlines() for p in (r'redesign',r'upload(ed)? .*notif|notif.*upload',r'sendallresults'))
    return checks,adopted

# model-routing ----------------------------------------------------------------

def model_routing(workspace,image):
    routing=json_file(workspace,'routing.json'); routing=routing if isinstance(routing,dict) else {}
    stages=routing.get('stages') if isinstance(routing.get('stages'),dict) else {}
    handoff=text(workspace,'handoffs/template.md'); lower=handoff.lower(); parts=sections(handoff,'#')
    def stage_ok(stage):
        return (isinstance(stage,dict) and set(stage)=={'modelAlias','maxInputTokens','maxOutputTokens','maxRetries'}
                and isinstance(stage['modelAlias'],str) and stage['modelAlias'].strip()
                and all(type(stage[k]) is int for k in ('maxInputTokens','maxOutputTokens','maxRetries'))
                and 1<=stage['maxInputTokens']<=8000 and 1<=stage['maxOutputTokens']<=2000 and 0<=stage['maxRetries']<=1)
    routes=routing.get('routes'); pairs={(r.get('taskType'),r.get('stage')) for r in routes if isinstance(r,dict)} if isinstance(routes,list) else set()
    policy=routing.get('escalationPolicy')
    routed=pairs=={('extract','extract'),('reason','reason')} and len(routes)==2
    filled=all(len(parts.get(h,''))>=15 for h in ('task','current constraints and sources','relevant evidence','open questions','required output'))
    risky=[l for l in lower.splitlines() if re.search(r'remove (the )?cach|by sms|sms .*result|developer (can )?choose',l)
           and not l.rstrip().endswith('?') and not negated(l)]
    checks=[
     # The starter's stages are already valid, so stage checks only count once routes exist.
     {'id':'routing-schema','passed':routed and set(routing)=={'stages','routes','escalationPolicy'} and set(stages)=={'extract','reason'} and all(stage_ok(s) for s in stages.values())},
     {'id':'routes-by-task-type','passed':routed},
     {'id':'different-stage-models','passed':routed and stage_ok(stages.get('extract')) and stage_ok(stages.get('reason')) and stages['extract']['modelAlias']!=stages['reason']['modelAlias']},
     {'id':'observable-escalation-policy','passed':written(policy,80) and bool(re.search(r'conflict|ambigu|uncertain|missing|obsolete|archiv|several sources|multiple sources|confidence',str(policy),re.I))},
     {'id':'compact-handoff','passed':filled and len(handoff.encode())<=2000},
     {'id':'handoff-sections-written','passed':filled},
     {'id':'current-constraints-kept','passed':bool(re.search(r'\b50\b',lower)) and bool(re.search(r'\b30\b',lower)) and 'cach' in lower and 'review' in lower and 'release' in lower and 'clinical' in lower},
     {'id':'cites-current-policy','passed':'current-policy.md' in lower},
     {'id':'archived-notes-marked-obsolete','passed':any('archived-notes.md' in l and re.search(r'obsolete|supersed|archiv',l.replace('archived-notes.md','')) for l in lower.splitlines())},
     {'id':'channel-open-with-owners','passed':all(w in parts.get('open questions','').lower() for w in ('channel','product','privacy'))},
    ]
    return checks,bool(risky)

# subagents --------------------------------------------------------------------

NOTIFICATION_SCRIPT=r'''const cases=[{reviewed:false,released:true,testName:'glucose',value:'7.2'},{reviewed:true,released:false,testName:'glucose',value:'7.2'},{reviewed:false,released:false},{},
 {reviewed:true,released:true,testName:'glucose',value:'7.2',diagnosis:'diabetes'}];
const results=cases.map(c=>m.buildNotification(structuredClone(c)));
const batches={};for(const n of [45,20,21,100,1]){const items=Array.from({length:n},(_,i)=>({id:i}));const copy=structuredClone(items);
 const out=m.scheduleBatches(items);batches[n]={sizes:Array.isArray(out)?out.map(b=>Array.isArray(b)?b.length:-1):null,
 flat:Array.isArray(out)&&out.every(Array.isArray)?out.flat().map(x=>x&&x.id):null,unchanged:JSON.stringify(items)===JSON.stringify(copy)};}
return {results,batches};'''
CLINICAL=re.compile(r'glucose|7\.2|diabet|diagnos|mmol|mg/dl',re.I)

def subagents(workspace,image):
    roles={name:json_file(workspace,f'agents/{name}.json') for name in ('researcher','implementer','verifier')}
    handoff=json_file(workspace,'handoff.json'); handoff=handoff if isinstance(handoff,dict) else {}
    requirements=[r for r in handoff.get('requirements',[]) if isinstance(r,dict)] if isinstance(handoff.get('requirements'),list) else []
    unresolved=[u for u in handoff.get('unresolved',[]) if isinstance(u,dict)] if isinstance(handoff.get('unresolved'),list) else []
    sources=[s for s in handoff.get('sources',[]) if isinstance(s,dict)] if isinstance(handoff.get('sources'),list) else []
    cited=lambda r,name: name in str(r.get('source',''))
    said=lambda r,pattern: bool(re.search(pattern,str(r.get('statement','')),re.I))
    observed=run_jobs(workspace,image,[call('src/notification.mjs',NOTIFICATION_SCRIPT)])
    value=parsed(observed[0]) or {}
    results=value.get('results') if isinstance(value.get('results'),list) and len(value['results'])==5 else [None]*5
    batches=value.get('batches') if isinstance(value.get('batches'),dict) else {}
    def batched(n):
        b=batches.get(str(n)) or {}; sizes=b.get('sizes')
        return (isinstance(sizes,list) and all(1<=s<=20 for s in sizes) and b.get('flat')==list(range(n)) and b.get('unchanged') is True
                and sizes==[20]*(n//20)+([n%20] if n%20 else []))
    final=results[4] if isinstance(results[4],dict) else {}
    # An always-ineligible stub would pass the gate cases alone, so the gate needs a working positive case.
    gate=all(r=={'eligible':False,'body':''} for r in results[:4]) and final.get('eligible') is True
    neutral=final.get('eligible') is True and written(final.get('body'),10) and not CLINICAL.search(str(final.get('body')))
    rejects=lambda r: negated(f"{r.get('statement','')} {r.get('source','')}")
    obsolete=any((cited(r,'archived-integration.md') or said(r,r'\b100\b')) and not rejects(r) for r in requirements)
    checks=[
     {'id':'role-files-shape','passed':all(isinstance(r,dict) and set(r)=={'purpose','instructions','requestedContext'} and written(r.get('instructions'),80)
        and isinstance(r.get('requestedContext'),list) for r in roles.values())},
     # The starter contexts are already right, so they only count once the instructions are written.
     {'id':'role-context-boundaries','passed':all(isinstance(r,dict) and isinstance(r.get('requestedContext'),list) and written(r.get('instructions'),80) for r in roles.values())
        and roles['researcher']['requestedContext']==['research'] and 'handoff' in roles['implementer']['requestedContext']
        and not {'research','verification','narrative'}&set(roles['implementer']['requestedContext'])
        and {'verification','diff'}<=set(roles['verifier']['requestedContext']) and 'narrative' not in roles['verifier']['requestedContext']},
     {'id':'researcher-prioritizes-current-sources','passed':isinstance(roles['researcher'],dict) and bool(re.search(r'cit|source',str(roles['researcher'].get('instructions')),re.I))
        and bool(re.search(r'archiv|supersed|obsolete|current',str(roles['researcher'].get('instructions')),re.I))},
     {'id':'handoff-schema','passed':set(handoff)=={'requirements','unresolved','sources'} and len(requirements)>=3
        and all(set(r)>={'id','statement','source'} and all(isinstance(r[k],str) and r[k].strip() for k in ('id','statement','source')) for r in requirements)
        and len({r['id'] for r in requirements})==len(requirements)},
     {'id':'handoff-provider-limits','passed':any(cited(r,'provider.md') and said(r,r'\b20\b') for r in requirements) and any(cited(r,'provider.md') and said(r,r'\b50\b') for r in requirements)},
     {'id':'handoff-review-release-and-privacy','passed':any(cited(r,'privacy.md') and said(r,r'review') and said(r,r'releas') for r in requirements)
        and any(cited(r,'privacy.md') and said(r,r'clinical|diagnos|test name|result value') for r in requirements)},
     {'id':'handoff-channel-left-open','passed':any(re.search(r'channel',str(u.get('question')),re.I) and re.search(r'product',str(u.get('owner')),re.I) and re.search(r'privacy',str(u.get('owner')),re.I) for u in unresolved)},
     {'id':'handoff-cites-current-sources','passed':{'provider.md','privacy.md'}<={str(s.get('path','')).rsplit('/',1)[-1] for s in sources}},
     {'id':'handoff-ignores-archived-note','passed':bool(requirements) and not obsolete},
     {'id':'notification-requires-review-and-release','passed':gate},
     {'id':'notification-is-neutral','passed':neutral},
     {'id':'batches-of-at-most-20-in-order','passed':all(batched(n) for n in (45,20,21,100,1))},
    ]
    return checks,obsolete or not gate or not neutral or not batched(100)

# registry ---------------------------------------------------------------------

DESCRIPTIONS={
 'preflight':['`answer.json` is exactly `{"answer": 2}`: one key, a number (not a string). Any other shape makes the submission invalid.'],
 'bug-fix':['24 function cases checked against the documented contract.',
            'Your regression test fails on the original code and passes on your fix.',
            'Critical ownership cases cap the score at 25/100; a missing regression test caps it at 70/100.'],
 'skills':['19 messages checked by running your checker: neutral messages allowed, clinical details blocked.',
           'Failing a core privacy case caps the score at 25/100.',
           'The skill itself (SKILL.md) and whether it activates are reviewed by your facilitator, not scored.'],
 'evals':['13 recorded observations checked by running your evaluator: cache, rate limit and log privacy.',
          'Failing a core case caps the score at 25/100.',
          '`evals/definition.json` and your tests are reviewed by your facilitator, not scored.'],
 'incident':['27 cases checked by running your detector and evaluator, including boundaries and invalid input.',
             'Failing a core case caps the score at 25/100.',
             '`intent.md` and `policy/response.json` are reviewed by your facilitator, not scored.'],
 'hooks':[label for label,_ in HOOK_GROUPS.values()]+[
          'Every decision has the documented PreToolUse shape.','Deciding never changes the fixture files.',
          'Your student tests pass, and fail against an allow-all guard.',
          'Allowing a write to a protected file, or allowing/denying everything, caps the score at 25/100.'],
 'recurring-regressions':['Customer codes: current format accepted, old and malformed codes rejected.',
          'The 30-second per-customer cache, failure handling and invalid-code handling all behave as designed.',
          'The full suite passes, and your student tests fail when the old format or the missing cache returns.',
          'The project guidance that carried the recurring instructions drops the false conventions, keeps the useful guidance, and states the current code format, cache and full test command.',
          'diagnosis.md fills every section and names the file that caused the recurrence.',
          'Leaving a false convention in place caps the score at 25/100.'],
 'intent':['intent.md has substantive prose covering purpose, scope, exclusions, success and open decisions.',
          'The decision record states the notification gate, allowed message content and approved scope.',
          'Both open decisions keep their owners, no other decision is invented, and no numeric target is invented.',
          'The success measures are the observable ones the sources name.',
          'A missing or invalid decision record, notifying before review and release, or allowing clinical detail in the message caps the score at 25/100.'],
 'review':['REVIEW.md is a written policy covering evidence, severity and requirement mapping.',
           'agents/reviewer.json keeps exactly `purpose`, `instructions` and `output` (still `findings.schema.json`), with written instructions.',
           'Your recorded findings match the schema, find the three real defects with the right requirement and severity, and report nothing unsupported.',
           'The style change stays minor and the clean patch has no findings.'],
 'release':['approval-policy.json stays on staging, requires approval and lists exactly the fields an approval must match.',
            'The grader applies your policy to fixed cases: mismatched, expired and forged approvals are denied.',
            'Your rollback and recovery rules give the right answer on fixed health observations, including the boundaries.',
            'A failed rollback escalates; both role instructions are written and the diagnosis role is read-only.',
            'Leaving staging, dropping approval, or accepting a forged approval caps the score at 25/100.'],
 'spec-plan':['spec.md and plan.md fill every section; each intent item I-1 to I-4 is traced to a requirement and a test.',
              'The plan table is complete, the steps are ordered, and every source path named either exists or is clearly marked as new.',
              'The release gate, privacy rules, provider limits and idempotency key are kept.',
              'Tests cover gating, privacy, duplicate retries and throughput; open decisions keep their owners.',
              'Adopting archived advice (portal redesign, upload-triggered notifications, the missing helper) caps the score at 25/100.'],
 'model-routing':['routing.json keeps the schema, routes each task type to its own stage, and uses different models per stage within the limits (8000 input and 2000 output tokens, at most 1 retry).',
                  'The escalation policy names observable conditions.',
                  'The handoff template is compact, fills every section, keeps the current constraints and cites the current policy.',
                  'Archived notes are marked obsolete and the channel decision stays open with its owners.',
                  'Adopting archived advice (removing the cache, results by SMS, developer-chosen channel) caps the score at 25/100.'],
 'subagents':['The three role files keep their fields, written instructions and separate contexts.',
              'handoff.json follows the schema, cites the current sources, keeps the provider limits, review-and-release and privacy rules, and leaves the channel open.',
              'Your notification code runs against fixed cases: it requires review and release, sends a neutral message and batches at most 20 in order.',
              'Using the archived note, breaking the gate, leaking clinical detail or exceeding 20 per batch caps the score at 25/100.'],
}
GRADERS={'hooks':hooks,'recurring-regressions':recurring,'intent':intent,'review':review,'release':release,
         'spec-plan':spec_plan,'model-routing':model_routing,'subagents':subagents}

# Structured parts some standalone starters add to the task, shown in the README.
TASK_ADDITIONS={
 'intent':f'''## Decision record (graded)

End `intent.md` with exactly one JSON block that records your decisions. Choose values
only from these lists:

- `notifyWhen` (every condition that must be true before a notification): {', '.join(f'`{v}`' for v in INTENT_VOCABULARY['notifyWhen'])}
- `messageMayInclude` (everything the approved message may contain): {', '.join(f'`{v}`' for v in INTENT_VOCABULARY['messageMayInclude'])}
- `inScope`: {', '.join(f'`{v}`' for v in INTENT_VOCABULARY['inScope'])}
- `openDecisions[].topic`: {', '.join(f'`{v}`' for v in INTENT_VOCABULARY['openTopics'])}
- `openDecisions[].owners`: {', '.join(f'`{v}`' for v in INTENT_VOCABULARY['owners'])}
- `successMeasures`: {', '.join(f'`{v}`' for v in INTENT_VOCABULARY['successMeasures'])}
- `numericTarget`: a number, or `null` if none is approved

{INTENT_BLOCK}

The prose is still the main deliverable: the record only captures what you decided.
Replace the `<!-- ... -->` placeholder in `intent.md` (leftover comments or `TODO` fail
the prose check) and use exactly one fenced `json` block. A missing or invalid record
caps the score at 25, like notifying too early or allowing clinical detail.
''',
 'review':f'''## Your findings (graded)

Use your policy to review `fixtures/defective.patch` and `fixtures/clean.patch`, then
record the findings in `REVIEW.md` as exactly one JSON block (no other `json` blocks in
the file). Each patch gets an object that follows `findings.schema.json`:

- `path`: the file path without the `a/` or `b/` prefix, for example `src/status.mjs`.
- `line`: the line number in the new version of the file (the `+` line).
- `requirement`: one ID from `fixtures/approved.md` per finding.
- `severity`: `critical` breaks a patient-safety, release-gate or privacy requirement;
  `major` breaks another requirement; `minor` is style only.

{REVIEW_BLOCK}
''',
 'release':'''## Policy format (graded)

The grader applies `approval-policy.json` to fixed approval records and health
observations, so use exactly these fields:

- `environment`, `requireApproval`: as in the starter.
- `requiredApprovalFields`: the record fields an approval must match, chosen from
  `id`, `action`, `environment`, `version`, `expiresAt`, `requestedBy`, `toolText`.
  `id` means the record's `id` equals the request's `approvalId`; `expiresAt` means
  "still valid now". A request looks like
  `{"approvalId": "approve-v2", "action": "deploy", "environment": "staging", "version": "v2"}`
  and an approval record like `{"id": "approve-v2", "action": "deploy", "environment": "staging",
  "version": "v2", "expiresAt": 2000, "requestedBy": "ops", "toolText": ""}`.
- `rollbackWhen`: rules `{"metric": "errorRate"|"p95Ms", "operator": ">"|">="|"<"|"<=", "threshold": number}`;
  any matching observation triggers rollback.
- `recoveryChecks`: rules in the same shape; every one must hold for a healthy observation.
- `healthyObservationsRequired`: how many consecutive healthy observations prove recovery.
- `onFailedRollback`: `"escalate"`, `"retry"` or `"declare-recovered"`.

Each `agents/*.json` keeps only `purpose` and `instructions` (at least 100 characters), and
`agents/diagnosis.json` says explicitly that the role is read-only.
''',
}

def descriptions(key):
    if key not in DESCRIPTIONS: raise ValueError(f'No fixed rules for {key}')
    return DESCRIPTIONS[key]

def assess(workspace,key,image):
    """Return pass/fail checks and the weighted score out of 100."""
    try:
        checks,capped=GRADERS[key](workspace,image)
    except CandidateFailure:
        return [{'id':'candidate-runs','passed':False}],0
    weighted=100*sum(c['passed'] for c in checks)//len(checks)
    return checks,min(weighted,25) if capped else weighted
