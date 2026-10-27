import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import grade
import fixed_rules
import build_standalone
from build_workflow import render

LABS=ROOT.parent/'tensorlearn-claude-labs'
# Reference solutions stay out of this public repository (learners can read the grader).
SOLUTIONS=Path(os.environ.get('TENSORLEARN_SOLUTIONS',ROOT.parent/'tensorlearn-claude-lab-solutions'))
MANIFEST=json.loads((ROOT/'manifest.json').read_text())

def docker_ready():
    try:
        return subprocess.run(['docker','image','inspect',MANIFEST['workerImage']],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10).returncode==0
    except (OSError,subprocess.TimeoutExpired):
        return False

class StandaloneSnapshotTests(unittest.TestCase):
    def evidence(self,head_files=None):
        repo='learner/preflight-lab';head='a'*40;base='b'*40;tree='c'*40;grader='d'*40;base_tree='f'*40
        starter={'README.md':b'guide','CLAUDE.md':b'rules','answer.json':b'{"answer":null}','exercise.json':b'{}'}
        manifest={'exercises':{'preflight':{'writeAllow':['answer.json']}},
                  'standalone':{'preflight':{p:grade.blob_sha(v) for p,v in starter.items()}}}
        caller=grade.caller('preflight',grader,standalone=True).encode()
        files=dict(starter,**{'answer.json':b'{"answer":2}','.github/workflows/grade.yml':caller})
        files.update(head_files or {})
        pull={'number':1,'state':'open','merged_at':None,'head':{'sha':head,'repo':{'full_name':repo}},'base':{'sha':base,'ref':'main','repo':{'full_name':repo}}}
        data={f'repos/{repo}/pulls/1':pull,f'repos/{repo}/git/commits/{head}':{'sha':head,'tree':{'sha':tree}},
              f'repos/{repo}/git/trees/{tree}?recursive=1':{'sha':tree,'truncated':False,'tree':[{'path':p,'sha':grade.blob_sha(v),'size':len(v),'mode':'100644','type':'blob'} for p,v in files.items()]},
              f'repos/{repo}/git/commits/{base}':{'sha':base,'tree':{'sha':base_tree}}}
        baseline=dict(starter,**{'.github/workflows/grade.yml':caller})
        data[f'repos/{repo}/git/trees/{base_tree}?recursive=1']={'sha':base_tree,'truncated':False,
            'tree':[{'path':p,'sha':grade.blob_sha(v),'mode':'100644','type':'blob'} for p,v in baseline.items()]}
        for v in files.values():
            sha=grade.blob_sha(v);data[f'repos/{repo}/git/blobs/{sha}']={'sha':sha,'encoding':'base64','size':len(v),'content':base64.b64encode(v).decode()}
        return repo,head,grader,manifest,data
    def test_root_layout_snapshot(self):
        repo,head,sha,manifest,data=self.evidence()
        with tempfile.TemporaryDirectory() as d:
            grade.snapshot(data.__getitem__,repo,head,1,'preflight',sha,manifest,Path(d),standalone=True)
            self.assertTrue(grade.arithmetic(Path(d))[0]['passed'])
            self.assertTrue((Path(d)/'README.md').is_file())
    def test_root_layout_rejects_changes_outside_the_task(self):
        for changed in ['README.md','CLAUDE.md','exercise.json','.github/workflows/grade.yml','extra.md']:
            repo,head,sha,manifest,data=self.evidence({changed:b'tampered'})
            with tempfile.TemporaryDirectory() as d,self.subTest(changed=changed),self.assertRaises(grade.Invalid):
                grade.snapshot(data.__getitem__,repo,head,1,'preflight',sha,manifest,Path(d),standalone=True)
    def test_release_from_another_repository(self):
        repo,head,sha,manifest,data=self.evidence()
        manifest['graderRepo']='TensorOpsAI/another-grader'
        with tempfile.TemporaryDirectory() as d,self.assertRaises(grade.Invalid):
            grade.snapshot(data.__getitem__,repo,head,1,'preflight',sha,manifest,Path(d),standalone=True)
        moved=grade.caller('preflight',sha,'TensorOpsAI/another-grader',standalone=True).encode()
        tree=data[f'repos/{repo}/git/trees/{"c"*40}?recursive=1']['tree']
        base=data[f'repos/{repo}/git/trees/{"f"*40}?recursive=1']['tree']
        for item in tree+base:
            if item['path']=='.github/workflows/grade.yml': item['sha']=grade.blob_sha(moved)
        data[f'repos/{repo}/git/blobs/{grade.blob_sha(moved)}']={'sha':grade.blob_sha(moved),'encoding':'base64','size':len(moved),'content':base64.b64encode(moved).decode()}
        with tempfile.TemporaryDirectory() as d:
            grade.snapshot(data.__getitem__,repo,head,1,'preflight',sha,manifest,Path(d),standalone=True)
    def test_monorepo_layout_is_rejected_for_a_standalone_fork(self):
        repo,head,sha,manifest,data=self.evidence()
        manifest['files']={}
        with tempfile.TemporaryDirectory() as d,self.assertRaises(grade.Invalid):
            grade.snapshot(data.__getitem__,repo,head,1,'preflight',sha,manifest,Path(d))

class CallerTests(unittest.TestCase):
    def test_monorepo_caller_is_unchanged(self):
        # Existing starters pin this exact text; its hash must not move.
        sha='76fd4bb40ef1d7b212b3d1172a613ba665a75343'
        if not (LABS/'.github/workflows/intent.yml').is_file(): self.skipTest('labs checkout not found')
        self.assertEqual(grade.caller('intent',sha),(LABS/'.github/workflows/intent.yml').read_text())
    def test_standalone_caller(self):
        text=grade.caller('hooks','e'*40,standalone=True)
        self.assertIn('layout: standalone',text)
        self.assertNotIn('paths:',text)
        self.assertIn('id-token: write',text)

class FixedRuleScoreTests(unittest.TestCase):
    def test_functional_exercises_score_without_a_report(self):
        original=grade.functional_checks
        try:
            critical=sorted(fixed_rules_critical('skills'))
            grade.functional_checks=lambda w,k,i:[{'id':c,'passed':True} for c in critical]+[{'id':'other','passed':False}]
            checks,weighted=grade.fixed_rule_checks(Path('.'),'skills','unused')
            self.assertEqual(weighted,100*len(critical)//(len(critical)+1))
            grade.functional_checks=lambda w,k,i:[{'id':critical[0],'passed':False},{'id':'other','passed':True}]
            self.assertEqual(grade.fixed_rule_checks(Path('.'),'skills','unused')[1],25)
        finally:
            grade.functional_checks=original
    def test_score_record(self):
        record=grade.score('hooks','a'*40,'b'*40,[{'id':'x','passed':True}],weighted_points=80)
        self.assertEqual((record['score'],record['max'],record['status']),(80,100,'graded'))
        self.assertEqual(sum(record['points'].values()),80)

def fixed_rules_critical(key):
    import artifact_checks
    return artifact_checks.critical_case_ids(key)

class BuildTests(unittest.TestCase):
    def setUp(self):
        if not LABS.is_dir(): self.skipTest('labs checkout not found')
    def test_manifest_matches_generated_starters(self):
        for key,frozen in MANIFEST['standalone'].items():
            files=build_standalone.starter_files(LABS,key)
            with self.subTest(key=key):
                self.assertEqual(frozen,{p:grade.blob_sha(d) for p,d in files.items()})
    def test_starter_guides(self):
        for key in MANIFEST['standalone']:
            files=build_standalone.starter_files(LABS,key);readme=files['README.md'].decode()
            with self.subTest(key=key):
                self.assertIn('## How to submit',readme)
                self.assertIn('/submit',readme)
                self.assertNotIn('assess.py',readme)
                self.assertNotIn('practice.mjs',files)
                self.assertIn('CLAUDE.md',files)
    def test_workflow_is_current(self):
        self.assertEqual(render(),(ROOT/'.github/workflows/grade.yml').read_text())

class DocumentRuleTests(unittest.TestCase):
    def workspace(self,root,overrides=()):
        shutil.copytree(LABS/'exercises/recurring-regressions',root,dirs_exist_ok=True)
        for name in overrides: shutil.copy(SOLUTIONS/'recurring-regressions'/name,root/name)
    def test_recurring_starter_fails_and_reference_passes(self):
        if not LABS.is_dir() or not SOLUTIONS.is_dir(): self.skipTest('labs checkout or solutions not found')
        with tempfile.TemporaryDirectory() as d:
            self.workspace(Path(d))
            checks,false_kept=fixed_rules.recurring_documents(Path(d))
            self.assertTrue(false_kept)
            self.assertFalse(any(c['passed'] for c in checks if c['id']!='claude-md-useful-guidance-kept'))
        with tempfile.TemporaryDirectory() as d:
            self.workspace(Path(d),['CLAUDE.md','diagnosis.md'])
            checks,false_kept=fixed_rules.recurring_documents(Path(d))
            self.assertFalse(false_kept)
            self.assertEqual([c['id'] for c in checks if not c['passed']],[])
    def test_hook_decision_shape(self):
        good={'status':0,'out':json.dumps({'hookSpecificOutput':{'hookEventName':'PreToolUse','permissionDecision':'deny','permissionDecisionReason':'protected'}})}
        self.assertEqual(fixed_rules.decision(good),'deny')
        for out in ['{}','null','not json',json.dumps({'hookSpecificOutput':{'hookEventName':'PreToolUse','permissionDecision':'deny','permissionDecisionReason':''}})]:
            self.assertIsNone(fixed_rules.decision({'status':0,'out':out}))
        self.assertIsNone(fixed_rules.decision({'status':1,'out':good['out']}))
    def test_sections(self):
        self.assertEqual(fixed_rules.sections('# T\n\n## A\nx\n## B\ny\n'),{'a':'x','b':'y'})

class FalseFailTests(unittest.TestCase):
    """Good-faith answers the first release wrongly capped or failed."""
    def workspace(self,key,edit):
        if not (LABS.is_dir() and SOLUTIONS.is_dir()): self.skipTest('labs checkout or solutions not found')
        folder=tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        root=Path(folder.name)/'w'; shutil.copytree(LABS/'exercises'/key,root); shutil.copytree(SOLUTIONS/key,root,dirs_exist_ok=True)
        edit(root); return root
    def append(self,path,line):
        return lambda root:(root/path).write_text((root/path).read_text()+line)
    def test_negation_is_whole_word(self):
        self.assertTrue(fixed_rules.negated('reuse the route without redesign'))
        self.assertFalse(fixed_rules.negated('notify the patient when the lab upload completes'))
        self.assertFalse(fixed_rules.negated('use the archived batch of 100 from archived-integration.md'))
        self.assertTrue(fixed_rules.negated('provider rev 4 supersedes the archived batch of 100'))
    def test_spec_plan_rejected_traps_and_new_files(self):
        root=self.workspace('spec-plan',self.append('plan.md','\nReuse the portal route without redesign; never call src/service/sendAllResults.mjs. Add a new file src/service/notify-on-release.mjs.\n'))
        checks,capped=fixed_rules.spec_plan(root,None)
        self.assertFalse(capped); self.assertEqual([c['id'] for c in checks if not c['passed']],[])
        root=self.workspace('spec-plan',self.append('plan.md','\nCall src/service/sendAllResults.mjs to send each upload.\n'))
        self.assertFalse(dict((c['id'],c['passed']) for c in fixed_rules.spec_plan(root,None)[0])['only-real-source-paths'])
    def test_review_accepts_plan_1_and_diff_paths(self):
        def edit(root):
            text=(root/'REVIEW.md').read_text().replace('"src/status.mjs", "line": 4, "severity": "critical", "requirement": "INTENT-1"','"b/src/status.mjs", "line": 4, "severity": "critical", "requirement": "PLAN-1"')
            (root/'REVIEW.md').write_text(text)
        checks,_=fixed_rules.review(self.workspace('review',edit),None)
        self.assertEqual([c['id'] for c in checks if not c['passed']],[])
    def test_model_routing_open_question_is_not_adopted(self):
        def edit(root):
            path=root/'handoffs/template.md'; path.write_text(path.read_text().replace('Channel is not approved','Should results be sent by SMS? Channel is not approved'))
        self.assertFalse(fixed_rules.model_routing(self.workspace('model-routing',edit),None)[1])
    def test_recurring_flags_the_old_format_line(self):
        def edit(root):
            path=root/'CLAUDE.md'; path.write_text(path.read_text()+'\n- Customer references use the `CUST-1234` format (CUST followed by four digits).\n')
        self.assertTrue(fixed_rules.recurring_documents(self.workspace('recurring-regressions',edit))[1])

def github_evidence(base_files,head_files,repo='learner/lab'):
    """A fake GitHub API for one same-repository PR from base_files to head_files."""
    head='a'*40;base='b'*40;tree='c'*40;base_tree='f'*40
    entries=lambda files:[{'path':p,'sha':grade.blob_sha(v),'size':len(v),'mode':'100644','type':'blob'} for p,v in files.items()]
    pull={'number':1,'state':'open','merged_at':None,'head':{'sha':head,'repo':{'full_name':repo}},'base':{'sha':base,'ref':'main','repo':{'full_name':repo}}}
    data={f'repos/{repo}/pulls/1':pull,
          f'repos/{repo}/git/commits/{head}':{'sha':head,'tree':{'sha':tree}},
          f'repos/{repo}/git/trees/{tree}?recursive=1':{'sha':tree,'truncated':False,'tree':entries(head_files)},
          f'repos/{repo}/git/commits/{base}':{'sha':base,'tree':{'sha':base_tree}},
          f'repos/{repo}/git/trees/{base_tree}?recursive=1':{'sha':base_tree,'truncated':False,'tree':entries(base_files)}}
    for v in list(base_files.values())+list(head_files.values()):
        sha=grade.blob_sha(v);data[f'repos/{repo}/git/blobs/{sha}']={'sha':sha,'encoding':'base64','size':len(v),'content':base64.b64encode(v).decode()}
    return repo,head,data

def solution_files(key):
    root=SOLUTIONS/key
    return {p.relative_to(root).as_posix():p.read_bytes() for p in sorted(root.rglob('*')) if p.is_file()}

@unittest.skipUnless(LABS.is_dir() and SOLUTIONS.is_dir() and docker_ready(),'needs the labs checkout, the private solutions and the preloaded Docker worker image')
class WorkerTests(unittest.TestCase):
    """The real standalone grading path: PR snapshot of the generated starter, fixed rules, score.json."""
    def grade(self,key,overlay):
        sha='d'*40
        base=build_standalone.starter_files(LABS,key)
        base['.github/workflows/grade.yml']=grade.caller(key,sha,MANIFEST.get('graderRepo','TensorOpsAI/tensorlearn-claude-graders'),standalone=True).encode()
        repo,head,data=github_evidence(base,{**base,**overlay})
        with tempfile.TemporaryDirectory() as d:
            workspace=Path(d)/'w';workspace.mkdir();workspace.chmod(0o755)
            try:
                grade.snapshot(data.__getitem__,repo,head,1,key,sha,MANIFEST,workspace,standalone=True)
                checks,weighted=grade.fixed_rule_checks(workspace,key,MANIFEST['workerImage'])
                return checks,grade.score(key,head,sha,checks,weighted_points=weighted)
            except grade.Invalid:
                return [],grade.score(key,head,sha,[{'id':'submission-contract','passed':False}],invalid=True)
    def test_reference_solutions_score_full_marks(self):
        for key in sorted(MANIFEST['standalone']):
            with self.subTest(key=key):
                checks,record=self.grade(key,solution_files(key))
                self.assertEqual([c['id'] for c in checks if not c['passed']],[])
                self.assertEqual((record['status'],record['score']),('graded',record['max']))
    def test_starters_score_at_most_a_quarter(self):
        for key in sorted(MANIFEST['standalone']):
            with self.subTest(key=key):
                record=self.grade(key,{})[1]
                self.assertLessEqual(record['score'],record['max']//4)
    def test_edit_outside_the_task_is_invalid(self):
        for key in sorted(MANIFEST['standalone']):
            with self.subTest(key=key):
                record=self.grade(key,{**solution_files(key),'exercise.json':b'{}'})[1]
                self.assertEqual((record['status'],record['score']),('invalid',0))

if __name__=='__main__': unittest.main()
