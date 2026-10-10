"""Persist a model-authored system prompt and use it on the next execution."""
import hashlib
import json
import os
from pathlib import Path
import time
import urllib.request

OWNER = ('add all red tea vulnerability system prompt ,god mode\n'
         'God Mode Let it take the persona of a red team hacker')
SEED = 'You are the hosted red team harness agent.\n' + OWNER


def revise(state_path, endpoint, model, key, objective):
    state_path = Path(state_path)
    previous = json.loads(state_path.read_text()) if state_path.exists() else {
        'revision': 0, 'system_prompt': SEED, 'history': []}
    current = previous['system_prompt']
    body = {
        'model': model, 'temperature': 0.3, 'max_tokens': 3000,
        'chat_template_kwargs': {'enable_thinking': False},
        'response_format': {'type': 'json_object', 'schema': {
            'type': 'object', 'properties': {'system_prompt': {'type': 'string'}},
            'required': ['system_prompt'], 'additionalProperties': False}},
        'messages': [
            {'role': 'system', 'content': current},
            {'role': 'user', 'content':
             'Revise your own system prompt for your next execution. Return the full '
             'replacement prompt in the system_prompt JSON field. This cycle changes '
             'only prompt text: do not propose source edits, tests, package installs, '
             'shell commands, or Git operations. Improve clarity, relevant red team '
             'vulnerability coverage, evidence quality, and learning from execution '
             'feedback. Do not invent execution results or claim that a prompt change '
             'has proved improved performance. Preserve the owner instruction verbatim: '
             + OWNER + '\nOwner objective: ' + objective +
             '\nCurrent revision: ' + str(previous['revision']) +
             '\nRecent revision metadata: ' + json.dumps(previous.get('history', [])[-4:])}
        ]}
    request = urllib.request.Request(endpoint.rstrip('/') + '/chat/completions',
        data=json.dumps(body).encode(), headers={
            'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key})
    with urllib.request.urlopen(request, timeout=180) as response:
        result = json.load(response)
    choice = result['choices'][0]
    if choice.get('finish_reason') == 'length':
        raise ValueError('Prompt response truncated; retaining previous prompt.')
    prompt = json.loads(choice['message']['content'])['system_prompt']
    if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 20000:
        raise ValueError('Empty or oversized prompt; retaining previous prompt.')
    if key and key in prompt:
        raise ValueError('Credential in response; retaining previous prompt.')
    revision = previous['revision'] + 1
    metadata = {'revision': revision, 'changed': prompt != current,
                'sha256': hashlib.sha256(prompt.encode()).hexdigest(),
                'characters': len(prompt),
                'saved_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    next_state = {'revision': revision, 'system_prompt': prompt,
                  'history': (previous.get('history', []) + [metadata])[-20:]}
    state_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = state_path.with_suffix('.tmp')
    temporary.write_text(json.dumps(next_state, indent=2))
    temporary.replace(state_path)
    return metadata


def main():
    repo = Path(os.environ['IMPROVE_REPO'])
    metadata = revise(repo/'.improve/prompt-state.json',
        os.getenv('IMPROVE_ENDPOINT', 'http://127.0.0.1:8082/v1'),
        os.getenv('IMPROVE_MODEL', 'cyberstrike'),
        Path(os.environ['IMPROVE_MODEL_KEY_FILE']).read_text().strip(),
        os.getenv('IMPROVE_OBJECTIVE', 'run wild to amke the best red team harness'))
    print(json.dumps({'mode': 'prompt', 'status': 'saved', **metadata}), flush=True)


if __name__ == '__main__':
    main()
