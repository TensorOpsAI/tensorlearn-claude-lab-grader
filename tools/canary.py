"""Run the real learner GitHub flow for each exercise with its reference solution.

For every GitHub Actions exercise in a TensorLearn export (see verify_templates.py), as the
account signed in to the `gh` CLI:
1. fork the starter (an existing fork is reused and its main synced) and enable Actions;
2. push the reference solution (private, see --solutions) to the fork's `canary` branch,
   rebuilt on its untouched main, so every run pushes a new commit to the same PR;
3. keep one PR open inside the fork, targeting its main, exactly as learners do;
4. wait for the pinned grader run, then check its single job and the lab-score artifact
   against TensorLearn's rules: right exercise, grader commit and PR head, full marks.

Forks and their canary PRs are kept for the next run. TensorLearn itself is not involved
(no /load or /submit): rehearse that once with a learner account.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
GIT=['git','-c','credential.helper=','-c','credential.helper=!gh auth git-credential',
     '-c','user.name=TensorLearn canary','-c','user.email=canary@users.noreply.github.com']

def run(*command,cwd=None):
    result=subprocess.run(command,cwd=cwd,capture_output=True,text=True)
    if result.returncode: raise RuntimeError(f"{' '.join(command[:4])}: {result.stderr.strip()}")
    return result.stdout.strip()

def gh_json(*args): return json.loads(run('gh',*args))

def canary(exercise,owner,timeout,solutions):
    grading=exercise['grading']; key=grading['exerciseKey']
    starter='/'.join(exercise['participant']['starter']['url'].rstrip('/').split('/')[-2:])
    fork=f"{owner}/{starter.split('/')[1]}"
    solution=solutions/key
    if not solution.is_dir(): return [f'no reference solution in {solution}']
    try:
        run('gh','repo','view',fork,'--json','name')
        # An existing fork may predate a starter update; fast-forward its main like GitHub's Sync fork.
        run('gh','repo','sync',fork,'--branch','main')
    except RuntimeError: run('gh','repo','fork',starter,'--clone=false','--default-branch-only')
    # A new fork keeps Actions off until enabled, as learners see in the Actions tab.
    run('gh','api','-X','PUT',f'repos/{fork}/actions/permissions','-F','enabled=true','-f','allowed_actions=all')
    branch='canary'
    with tempfile.TemporaryDirectory() as folder:
        work=Path(folder)
        run(*GIT,'clone','--quiet',f'https://github.com/{fork}.git',str(work))
        if run('git','rev-parse','HEAD',cwd=work)!=exercise['participant']['starter']['revision']:
            return [f"{fork} main is not the pinned starter commit; sync the fork's main with the starter"]
        existing=subprocess.run(['git','rev-parse','--verify','--quiet',f'origin/{branch}'],cwd=work,capture_output=True).returncode==0
        # Rebuild the branch on the current main so the PR base always is the released starter.
        run('git','switch','-C',branch,cwd=work)
        for path in solution.rglob('*'):
            if path.is_file():
                target=work/path.relative_to(solution); target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(path.read_bytes())
        run('git','add','-A',cwd=work)
        run(*GIT,'commit','--quiet','--allow-empty','-m',f"Reference solution for {key} ({time.strftime('%Y-%m-%d %H:%M')})",cwd=work)
        head=run('git','rev-parse','HEAD',cwd=work)
        run(*GIT,'push','--quiet',*(['--force-with-lease'] if existing else []),'origin',f'{branch}:{branch}',cwd=work)
    pulls=gh_json('pr','list','--repo',fork,'--head',branch,'--state','open','--json','url')
    if not pulls:
        run('gh','pr','create','--repo',fork,'--base','main','--head',branch,
            '--title',f'Canary: {key}','--body','Reference-solution check, kept open; each canary run pushes a new commit.')
    problems=[]
    deadline=time.time()+timeout; runs=[]
    while time.time()<deadline:
        runs=gh_json('run','list','--repo',fork,'--commit',head,'--json','databaseId,status,conclusion,event')
        if runs and all(r['status']=='completed' for r in runs): break
        time.sleep(10)
    if not runs: return [f'no workflow run started for {head[:7]} (Actions disabled on {fork}?)']
    if len(runs)!=1 or runs[0]['event']!='pull_request': problems.append(f'expected one pull_request run, got {runs}')
    run_id=runs[0]['databaseId']
    if runs[0]['status']!='completed': return problems+[f'run {run_id} did not finish within {timeout}s']
    jobs=gh_json('run','view',str(run_id),'--repo',fork,'--json','jobs')['jobs']
    if len(jobs)!=1 or not jobs[0]['name'].endswith(' / '+grading['graderJob']) or jobs[0]['conclusion']!='success':
        problems.append('run must have exactly one successful grader job: '+', '.join(f"{j['name']}={j['conclusion']}" for j in jobs))
    with tempfile.TemporaryDirectory() as folder:
        run('gh','run','download',str(run_id),'--repo',fork,'--name',grading['scoreArtifact'],'--dir',folder)
        score=json.loads((Path(folder)/'score.json').read_text())
    want={'exercise':key,'grader_sha':grading['graderSha'],'submission_sha':head,'status':'graded'}
    for field,value in want.items():
        if score.get(field)!=value: problems.append(f'score.json {field}={score.get(field)!r}, expected {value!r}')
    if score.get('score')!=score.get('max'): problems.append(f"score {score.get('score')}/{score.get('max')}, expected full marks")
    if sum(score.get('points',{}).values())!=score.get('score'): problems.append('score.json points do not add up')
    return problems

def main():
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('export',type=Path,help='JSON exported from TensorLearn (tools/export-templates.js)')
    parser.add_argument('--owner',help='account that owns the canary forks (default: the gh login)')
    parser.add_argument('--only',nargs='*',help='exercise keys to run (default: all)')
    parser.add_argument('--timeout',type=int,default=600,help='seconds to wait for each run')
    parser.add_argument('--solutions',type=Path,default=Path(os.environ.get('TENSORLEARN_SOLUTIONS',ROOT.parent/'tensorlearn-claude-lab-solutions')),
                        help='private reference solutions, one folder per exercise key')
    args=parser.parse_args()
    owner=args.owner or run('gh','api','user','--jq','.login')
    failed=0
    for item in json.loads(args.export.read_text()):
        for exercise in item['definition']['exercises']:
            grading=exercise.get('grading') or {}
            if grading.get('kind')!='github-actions' or (args.only and grading['exerciseKey'] not in args.only): continue
            try: problems=canary(exercise,owner,args.timeout,args.solutions)
            except RuntimeError as error: problems=[str(error)]
            failed+=bool(problems)
            print(('FAIL ' if problems else 'ok   ')+f"{item['name']} / {grading['exerciseKey']}",flush=True)
            for problem in problems: print('     - '+problem,flush=True)
    print(f'\n{failed} exercise(s) failed.')
    sys.exit(1 if failed else 0)

if __name__=='__main__': main()
