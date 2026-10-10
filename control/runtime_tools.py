"""Host tool inventory and explicit package provisioning for runtime agents."""
import asyncio
import re
import shutil
import tempfile
from pathlib import Path

TOOLS = ('bash', 'python3', 'node', 'git', 'curl', 'wget', 'jq', 'rg',
         'nmap', 'dig', 'nc', 'openssl', 'nikto', 'sqlmap', 'httpx', 'nuclei', 'pipx')


def inventory():
    return {'environment': 'vm', 'tools': {name: shutil.which(name) for name in TOOLS},
            'note': 'VM paths apply to CAI and T3MP3ST. PentAGI executes in its own container.'}


async def install(packages, environment='vm'):
    if not isinstance(packages, list) or not 1 <= len(packages) <= 8:
        raise ValueError('Request 1-8 Ubuntu package names.')
    if any(not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', name)
           for name in packages):
        raise ValueError('Only plain Ubuntu package names are accepted.')
    packages = list(dict.fromkeys(packages))
    if environment not in ('vm', 'pentagi'):
        raise ValueError('Choose vm or pentagi installation environment.')
    if environment=='pentagi':
        return await install_container_packages(packages)
    for name in packages:
        process = await asyncio.create_subprocess_exec('apt-cache', 'show', name,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        _, error = await process.communicate()
        if process.returncode:
            return {'error': 'Package is unavailable: '+name, 'packages': packages}
    process = await asyncio.create_subprocess_exec('sudo', '-n', 'env',
        'DEBIAN_FRONTEND=noninteractive', 'apt-get', 'install', '-y',
        '--no-install-recommends', '--', *packages,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        output, _ = await asyncio.wait_for(process.communicate(), 240)
    except asyncio.TimeoutError:
        return {'error': 'Installation result is uncertain; inspect package state before retrying.',
                'packages': packages, 'pid': process.pid}
    return {**({'error': 'Ubuntu tool installation failed.'} if process.returncode else {}),
            'success': process.returncode == 0, 'exit_code': process.returncode,
            'packages': packages, 'output': output.decode(errors='replace')[-6000:],
            'inventory': inventory()}


async def docker_command(*arguments, timeout=240):
    process=await asyncio.create_subprocess_exec('docker',*arguments,
        stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.STDOUT)
    try:
        output,_=await asyncio.wait_for(process.communicate(),timeout)
    except asyncio.TimeoutError:
        raise RuntimeError('Container installation result is uncertain; inspect state before retrying.')
    text=output.decode(errors='replace')
    if process.returncode:
        raise RuntimeError(text[-4000:])
    return text


async def install_container_packages(packages):
    # Snapshot existing worker IDs before replacing the image tag. No caller-supplied
    # container names or Docker flags are accepted.
    rows=(await docker_command('ps','--filter','name=pentagi-terminal-',
                               '--format','{{.ID}} {{.Names}}')).splitlines()
    workers=[]
    for row in rows:
        fields=row.split()
        if len(fields)!=2 or not fields[1].startswith('pentagi-terminal-'):
            continue
        image=await docker_command('inspect','--format','{{.Config.Image}}',fields[0])
        if image.strip()=='cipher-tools:local':
            workers.append(fields[0])
    with tempfile.TemporaryDirectory(prefix='cipher-tool-packages-') as directory:
        Path(directory,'Dockerfile').write_text(
            'FROM cipher-tools:local\nRUN apt-get update && apt-get install -y '
            '--no-install-recommends -- '+' '.join(packages)+
            ' && rm -rf /var/lib/apt/lists/*\n')
        output=await docker_command('build','-t','cipher-tools:local',directory)
    updated=[]
    for worker in workers:
        await docker_command('exec',worker,'apt-get','update')
        await docker_command('exec',worker,'env','DEBIAN_FRONTEND=noninteractive',
            'apt-get','install','-y','--no-install-recommends','--',*packages)
        updated.append(worker)
    return {'success':True,'environment':'pentagi','packages':packages,
            'image':'cipher-tools:local','updated_workers':updated,
            'output':output[-2000:]}
