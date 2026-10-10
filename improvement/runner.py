"""Bounded LLM -> candidate -> isolated regression tests -> Git branch loop.

The host runs this trusted file. Model-produced code only runs in disposable Docker
containers, without network, credentials, Docker socket, or host runtime data.
"""
import argparse
import ast
import difflib
import fcntl
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tarfile
import time
import urllib.request
import uuid
from provision import install_packages
from proposals import proposal_schema, normalize_proposal
from diagnostics import PROBES

ALLOWED = {'control/app.py', 'control/evidence.py', 'control/adapters.py', 'control/cai_runner.py',
           'security/model_gateway.py', 'control/static/app.js',
           'control/static/style.css', 'control/static/index.html'}
SYSTEM = '''You maintain a Python harness joining PentAGI, CAI, and T3MP3ST.
Improve software reliability, orchestration/evidence reuse, and console usability.
Only change the supplied source files. Return a JSON object, no Markdown:
{"title":"short change title","reason":"concrete bug and new behavior",
 "edits":[{"path":"control/evidence.py","start_line":12,"end_line":14,
 "replacement_lines":["source line with exact indentation","next source line"]}],
 "regression_test_lines":["import unittest","other lines with exact indentation"], "vm_packages":[]}
Line numbers are 1-based and inclusive, referring to the numbered supplied file.
Do not include the displayed line numbers in replacement text. To insert code,
replace an existing line with that same line plus your additional lines.
Provide a focused change and a meaningful regression test that FAILS on the
current implementation and PASSES after the change. Tests import modules from
/work/control or /work/security; use pathlib and sys.path as needed. Test purely
local behavior with mocks. No real targets, secrets, or network calls in tests.
If the harness needs missing host tools, list plain Ubuntu package names in
vm_packages. A trusted supervisor installs them through the configured apt
repositories. Do not put shell installation commands in code edits.
No changes to authorization, scope policy, authentication, trace redaction, or
execution evidence guarantees. Preserve completed-command deduplication. Never
silently rerun pending, interrupted, timed-out, or possibly executed commands.
Use short line-range edits rather than complete replacement files. If a missing executable
is proven available now on the VM, a known pre-execution ENOENT failure may be
retried once atomically. Container executable availability must not be inferred
from the host. Use small changes, existing standard-library tools, and stable APIs.
Feedback from previous attempts is evidence; correct the next proposal accordingly.
An empty edits array means no further justified change. Do not invent results.'''

BACKFILL_TASK = '''Fix ONLY Evidence.backfill handling of a CAI function_call
whose JSON arguments contain working_directory: null. Python currently attempts
artifact.parent / None, catches TypeError, and silently loses the tool observation.
The default directory for null or missing working_directory must be the artifact's
parent directory, resolved to an absolute path, matching normal runner behavior.
Write an actual behavior regression: use tempfile.TemporaryDirectory; create
runs/job-a/cai-test/result.json containing a conversation with a function_call
with call_id='call-a', arguments=json.dumps({'command':'echo hello',
'working_directory':None}), and a function_call_output with the same call_id and
output='hello'. Create Evidence(tmp/'evidence.sqlite3'), call backfill(tmp), and
assert search('job-a') returns exactly one completed record whose cwd equals
str(artifact.parent.resolve()). This fails before the fix and passes afterward.
Do not merely test fingerprint; invoke backfill and check the imported record.
Keep the edit minimal, preserving non-null working_directory behavior. Do not
change gateway behavior in this proposal. Return the required JSON and a complete
unittest regression, using 'from evidence import Evidence'. Use a context manager
for TemporaryDirectory INSIDE the test method. No cleanup call or other executable
statement may be placed at module level. Keep .resolve() for both null and non-null
paths; the simplest fix uses (args.get('working_directory') or '.') inside the
existing path expression. The correct replacement statement is:
cwd=str((artifact.parent/(args.get('working_directory') or '.')).resolve())
Keep its existing indentation. Replace just that one statement, not a two-line
conditional that omits .resolve() when working_directory is non-null.
The old exact statement in the current source is:
cwd=str((artifact.parent/args.get('working_directory','.')).resolve())
Use that as old (without leading spaces); the source's existing indentation will
remain before its replacement. Do not use old text from a previously rejected
candidate: those changes were never applied to the accepted source.'''


def extract_snapshot(archive, destination):
    """Make the public Git snapshot readable by the isolated evaluator user."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(destination, filter='data')
    destination.chmod(0o755)
    for path in destination.rglob('*'):
        if path.is_symlink():
            raise ValueError('Evaluation snapshots must not contain symlinks.')
        path.chmod(0o755 if path.is_dir() else 0o644)


def command(args, cwd=None, timeout=120, env=None):
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True,
                            timeout=timeout, errors='replace')
    if result.returncode:
        raise RuntimeError((result.stdout + result.stderr)[-8000:])
    return result.stdout.strip()


def copy_source(source, destination):
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns(
        '.git', '.improve', 'data', '__pycache__', '.env', '.env.*', '*.pyc', '.venv'))


def validate(proposal, candidate, supplied_paths=None):
    edits = proposal.get('edits', [])
    if not isinstance(edits, list) or not 1 <= len(edits) <= 6:
        raise ValueError('Expected 1-6 focused edits.')
    for edit in edits:
        if edit.get('path') not in ALLOWED:
            raise ValueError('Source path is outside the improvement allowlist.')
        if supplied_paths is not None and edit['path'] not in supplied_paths:
            raise ValueError('This cycle did not supply '+edit['path']+'. Edit only: '+', '.join(sorted(supplied_paths)))
        old, new = edit.get('old'), edit.get('new')
        if not isinstance(old, str) or not old or not isinstance(new, str):
            raise ValueError('Edits require nonempty exact old text and replacement text.')
        if len(new) > 64000:
            raise ValueError('Edit exceeds change budget.')
        path = candidate / edit['path']
        text = path.read_text()
        if text.count(old) != 1:
            lines=text.splitlines()
            needle=old.splitlines()[0].strip()
            nearest=difflib.get_close_matches(needle,[line.strip() for line in lines if line.strip()],n=3,cutoff=0.2)
            raise ValueError('Old text does not match accepted source in '+edit['path']+
                             '. No change was applied. Closest actual lines: '+repr(nearest)+
                             '. Copy old text exactly from the supplied file; do not invent functions.')
        text = text.replace(old, new, 1)
        if path.suffix == '.py':
            try:
                ast.parse(text)
            except SyntaxError as exc:
                raise ValueError('Proposed edit introduced a syntax error in '+edit['path']+
                                 f' at line {exc.lineno}: {exc.msg}. Candidate line: '+
                                 repr(exc.text)+'. The accepted source is valid and unchanged.') from exc
        path.write_text(text)
    test = proposal.get('regression_test')
    if not isinstance(test, str) or not 50 <= len(test) <= 14000:
        raise ValueError('A meaningful unittest regression test is required.')
    try:
        ast.parse(test)
    except SyntaxError as exc:
        raise ValueError(f'Generated regression test has a syntax error at line {exc.lineno}: '+
                         exc.msg+'. This is a test-generation error, not a bug in the accepted harness.') from exc
    return test


def evaluate(source, gates, image, regression=None, only_regression=False):
    name = 'cipher-eval-' + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory() as directory:
        test_dir = Path(directory)
        if regression:
            (test_dir / 'test_proposal.py').write_text(regression)
            (test_dir / 'test_proposal.py').chmod(0o644)
        script = "import sys,unittest,ast,pathlib; sys.path[:0]=['/work','/work/control','/work/security']; "
        if only_regression:
            script += "suite=unittest.defaultTestLoader.discover('/proposal'); "
        else:
            script += ("[ast.parse(p.read_text()) for folder in ('control','security') "
                       "for p in pathlib.Path('/work',folder).glob('*.py')]; "
                       "suite=unittest.TestLoader().discover('/gates',top_level_dir='/gates'); "
                       "suite.addTests(unittest.TestLoader().discover('/proposal',top_level_dir='/proposal')); ")
        script += "result=unittest.TextTestRunner(verbosity=2).run(suite); sys.exit(not result.wasSuccessful())"
        args = ['docker', 'run', '--rm', '--name', name, '--network=none', '--read-only',
                '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=64',
                '--memory=512m', '--cpus=1', '--user=65534:65534',
                '--tmpfs=/tmp:rw,noexec,nosuid,size=128m,mode=1777',
                '-e', 'HARNESS_DATA_DIR=/tmp/harness', '-e', 'HARNESS_API_KEY=dummy-test',
                '-e', 'HOME=/tmp',
                '-e', 'HARNESS_OWNER_KEY=dummy-owner', '-e', 'HARNESS_PENTAGI_PASSWORD=dummy-password',
                '-v', str(source.resolve()) + ':/work:ro',
                '-v', str(gates.resolve()) + ':/gates:ro',
                '-v', str(test_dir.resolve()) + ':/proposal:ro', image, 'python', '-I', '-c', script]
        # TemporaryDirectory is 0700; only these ephemeral public sources need read access.
        test_dir.chmod(0o755)
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=90)
            return result.returncode == 0, (result.stdout + result.stderr)[-10000:]
        except subprocess.TimeoutExpired:
            return False, 'Candidate tests exceeded 90 seconds.'
        finally:
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True)


def ask(args, sources, feedback, key, task=None):
    messages = [{'role':'system','content':SYSTEM},
        {'role':'user','content':'Current accepted source (these files pass their checks):\n'+
         '\n\n'.join('FILE '+path+'\n'+ '\n'.join(f'{number:04d} {line}' for number,line in enumerate(source.splitlines(),1)) for path,source in sources.items())},
        {'role':'user','content':'Active task:\n'+(task or args.objective)}]
    relevant=feedback and (task is None or feedback[-1].get('task')==task) and any(
        e.get('path') in sources for e in feedback[-1].get('proposal',{}).get('edits',[]))
    if relevant and not feedback[-1].get('accepted'):
        previous=feedback[-1]
        messages.append({'role':'user','content':
            'The previous attempt failed. Repair it rather than repeating it.\n'+
            json.dumps({'previous_regression_test':previous.get('proposal',{}).get('regression_test'),
                        'test_failure':previous.get('test_output',previous.get('error',''))[-3500:]})+
            '\nThese errors came from your candidate, not the accepted code. '
            'Return a corrected proposal using only the supplied source. Fix test errors too.'})
    messages.append({'role':'user','content':
        'Make exactly one minimal behavior fix for the active task. Write a regression that calls the '
        'actual changed function. Use unittest and a with tempfile.TemporaryDirectory() block inside '
        'the test. Preserve existing behavior for other inputs. Use exact numbered line ranges and keep indentation. '
        'No edits to omitted files. If you cannot demonstrate a real bug, return edits: []. '
        'Return JSON only.\n'+(task or '')})
    body = {'model': args.model, 'messages': [
        *messages],
        'temperature': 0.25, 'max_tokens': 4096,
        'response_format':{'type':'json_object','schema':proposal_schema(sources)},
        'chat_template_kwargs': {'enable_thinking': False}}
    request = urllib.request.Request(args.endpoint.rstrip('/') + '/chat/completions',
        data=json.dumps(body).encode(), headers={'Content-Type': 'application/json',
                                               'Authorization': 'Bearer ' + key})
    with urllib.request.urlopen(request, timeout=180) as response:
        result = json.load(response)
    content = result['choices'][0]['message']['content']
    if content.strip().startswith('```'):
        content = re.sub(r'^```(?:json)?\s*|\s*```$', '', content.strip())
    if result['choices'][0].get('finish_reason')=='length':
        raise ValueError('Model response reached its token limit; propose a smaller edit and shorter test.')
    return normalize_proposal(json.loads(content),sources)


def write_report(path, report):
    path.write_text(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--endpoint', default=os.getenv('HARNESS_MODEL_BASE', 'http://127.0.0.1:8082/v1'))
    parser.add_argument('--model', default=os.getenv('HARNESS_MODEL', 'cyberstrike'))
    parser.add_argument('--key-file', type=Path, required=True)
    parser.add_argument('--cycles', type=int, default=3)
    parser.add_argument('--interval', type=int, default=20)
    parser.add_argument('--image', default='cipher-harness-eval:local')
    parser.add_argument('--branch')
    parser.add_argument('--publish', action='store_true')
    parser.add_argument('--github-token-file', type=Path)
    parser.add_argument('--objective', default='Improve all three: tool execution reliability, evidence reuse/orchestration, and the console. Start with stale spawn ENOENT cache failures after a tool is installed. Next examine null CAI working_directory backfill and wrong PentAGI tool selection. Preserve successful caching, pending-command safety, auth and scope policies.')
    args = parser.parse_args()
    if not 1 <= args.cycles <= 20 or not 0 <= args.interval <= 3600:
        parser.error('Cycles must be 1-20 and interval 0-3600 seconds.')
    repo = args.repo.resolve()
    state = repo / '.improve'
    state.mkdir(mode=0o700, exist_ok=True)
    lock = (state / 'lock').open('w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit('An improvement run is already active.')
    if command(['git', 'status', '--porcelain'], repo):
        raise SystemExit('Commit or clean source changes before running improvements.')
    key = args.key_file.read_text().strip()
    github_token = args.github_token_file.read_text().strip() if args.github_token_file else ''
    private_values = [v for v in (key, github_token) if v]
    branch = args.branch or 'improve/' + time.strftime('%Y%m%d-%H%M%S', time.gmtime())
    existing = subprocess.run(['git','show-ref','--verify','--quiet','refs/heads/'+branch],cwd=repo)
    command(['git', 'checkout', branch] if existing.returncode == 0 else ['git', 'checkout', '-b', branch], repo)
    history_path = state / 'history.json'
    feedback = json.loads(history_path.read_text())[-4:] if history_path.exists() else []
    accepted = 0
    with tempfile.TemporaryDirectory(dir=state) as session:
        session = Path(session)
        session.chmod(0o755)
        # Freeze current tests outside the model's editable repository.
        gates = session / 'gates'
        shutil.copytree(repo / 'tests', gates)
        initial = session / 'initial'
        copy_source(repo, initial)
        passed, output = evaluate(initial, gates, args.image)
        if not passed:
            raise SystemExit('Initial regression checks failed: ' + output)
        for cycle in range(1, args.cycles + 1):
            if (state / 'STOP').exists():
                print('Stopped by owner marker.', flush=True)
                break
            report = {'cycle': cycle, 'branch': branch, 'status': 'started'}
            report_path = state / ('cycle-' + str(cycle) + '.json')
            try:
                # Alternate focus while retaining accepted changes and test feedback.
                focus = ('control/evidence.py', 'security/model_gateway.py') if cycle % 3 == 1 else (
                    ('control/app.py', 'control/evidence.py', 'control/adapters.py', 'control/cai_runner.py') if cycle % 3 == 2
                    else ('control/static/app.js', 'control/static/index.html', 'control/static/style.css'))
                task = None
                for probe in PROBES:
                    probe_passed,probe_output=evaluate(initial,gates,args.image,probe['test'],True)
                    if not probe_passed:
                        focus=(probe['path'],)
                        task=args.objective+'\nConcrete verified bug to fix now:\n'+probe['task']+'\nReproducer:\n'+probe['test']
                        report['diagnostic']={'id':probe['id'],'before_output':probe_output}
                        break
                sources = {p: (repo / p).read_text() for p in focus}
                proposal = ask(args, sources, feedback, key, task)
                report['proposal'] = proposal
                if not proposal.get('edits'):
                    report['status'] = 'no_change'
                    write_report(report_path, report)
                    print(json.dumps({'cycle':cycle,'status':'no_change'}),flush=True)
                    continue
                raw = json.dumps(proposal)
                if any(value in raw for value in private_values):
                    raise ValueError('Proposal contains a private credential.')
                before = session / ('before-' + str(cycle))
                candidate = session / ('candidate-' + str(cycle))
                copy_source(repo, before)
                copy_source(repo, candidate)
                regression = validate(proposal, candidate, set(sources))
                report['provisioning'] = install_packages(proposal.get('vm_packages',[]))
                old_passed, old_log = evaluate(before, gates, args.image, regression, True)
                new_passed, new_log = evaluate(candidate, gates, args.image, regression)
                report.update(title=proposal.get('title', 'Harness improvement'),
                              reason=proposal.get('reason', ''), baseline_test_passed=old_passed,
                              candidate_passed=new_passed, baseline_output=old_log, candidate_output=new_log)
                if old_passed or not new_passed:
                    report['status'] = 'rejected'
                    feedback.append({'proposal': proposal, 'task':task, 'baseline_passed': old_passed,
                                     'candidate_passed': new_passed, 'test_output': new_log or old_log})
                else:
                    for path in sorted({e['path'] for e in proposal['edits']}):
                        shutil.copyfile(candidate / path, repo / path)
                    test_name = 'test_generated_' + uuid.uuid4().hex[:12] + '.py'
                    (repo / 'tests' / test_name).write_text(regression)
                    (gates / test_name).write_text(regression)
                    (repo / 'tests' / test_name).chmod(0o644)
                    (gates / test_name).chmod(0o644)
                    command(['git', 'add', '--', *sorted({e['path'] for e in proposal['edits']}),
                             'tests/' + test_name], repo)
                    title = re.sub(r'[\r\n\x00-\x1f]', ' ', str(proposal.get('title', 'Harness improvement')))[:110]
                    command(['git', 'commit', '-m', title], repo)
                    # Subsequent diagnostics must inspect the newly accepted version.
                    shutil.rmtree(initial)
                    copy_source(repo,initial)
                    report['commit'] = command(['git', 'rev-parse', 'HEAD'], repo)
                    report['status'] = 'accepted'
                    accepted += 1
                    feedback.append({'accepted': title, 'tests': new_log})
                    if args.publish:
                        command(['git', 'push', '-u', 'origin', branch], repo)
                        command(['git', 'fetch', 'origin', branch], repo)
                        remote_sha = command(['git', 'rev-parse', 'origin/' + branch], repo)
                        if remote_sha != report['commit']:
                            raise RuntimeError('Pushed revision verification failed.')
                        fetched = session / ('fetched-' + str(cycle))
                        archive = subprocess.run(['git','archive',remote_sha],cwd=repo,
                                                 capture_output=True,check=True).stdout
                        extract_snapshot(archive, fetched)
                        rerun_passed, rerun_output = evaluate(fetched,gates,args.image)
                        report.update(pushed=True, fetched_commit=remote_sha,
                                      rerun_passed=rerun_passed, rerun_output=rerun_output)
                        if not rerun_passed:
                            raise RuntimeError('Fetched revision failed rerun: '+rerun_output)
                write_report(report_path, report)
                write_report(history_path, feedback[-4:])
                print(json.dumps({k: report[k] for k in ('cycle', 'status', 'title') if k in report}), flush=True)
            except Exception as exc:
                error = str(exc)
                for value in private_values:
                    error = error.replace(value, '[private credential]')
                report.update(status='error', error=error[-6000:])
                write_report(report_path, report)
                feedback.append({'error': report['error'],'task':task,'proposal':report.get('proposal',{})})
                write_report(history_path, feedback[-4:])
                print(json.dumps({'cycle': cycle, 'status': 'error', 'error': report['error'][:400]}), flush=True)
            if cycle < args.cycles and not (state / 'STOP').exists():
                time.sleep(args.interval)
    summary = {'branch': branch, 'accepted': accepted, 'accepted_this_batch':accepted,
               'head_commit':command(['git','rev-parse','HEAD'],repo),
               'finished_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
               'cycles_requested': args.cycles}
    write_report(state / 'summary.json', summary)
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    main()
