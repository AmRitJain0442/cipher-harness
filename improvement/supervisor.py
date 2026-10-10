"""Cloud service: run bounded improvement batches until the owner stops it."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def main():
    repo = Path(os.environ['IMPROVE_REPO'])
    interval = int(os.getenv('IMPROVE_BATCH_INTERVAL', '900'))
    runner = Path(__file__).with_name('runner.py')
    args = [sys.executable,str(runner),'--repo',str(repo),
            '--key-file',os.environ['IMPROVE_MODEL_KEY_FILE'],
            '--endpoint',os.getenv('IMPROVE_ENDPOINT','http://127.0.0.1:8082/v1'),
            '--model',os.getenv('IMPROVE_MODEL','cyberstrike'),
            '--cycles',os.getenv('IMPROVE_CYCLES','3'),
            '--branch','improve/autonomous','--publish']
    if os.getenv('IMPROVE_GITHUB_TOKEN_FILE'):
        args.extend(['--github-token-file',os.environ['IMPROVE_GITHUB_TOKEN_FILE']])
    while not (repo/'.improve/STOP').exists():
        print('Starting recursive improvement batch.',flush=True)
        result = subprocess.run(args)
        print(json.dumps({'batch_exit_code':result.returncode,'next_batch_seconds':interval}),flush=True)
        # Sleep in short increments so the owner stop marker remains responsive.
        for _ in range(max(1,interval//5)):
            if (repo/'.improve/STOP').exists():
                return
            time.sleep(5)


if __name__=='__main__':
    main()
