"""Host tool inventory and explicit package provisioning for runtime agents."""
import asyncio
import re
import shutil

TOOLS = ('bash', 'python3', 'node', 'git', 'curl', 'wget', 'jq', 'rg',
         'nmap', 'dig', 'nc', 'openssl', 'nikto', 'sqlmap', 'pipx')


def inventory():
    return {'environment': 'vm', 'tools': {name: shutil.which(name) for name in TOOLS},
            'note': 'VM paths apply to CAI and T3MP3ST. PentAGI executes in its own container.'}


async def install(packages):
    if not isinstance(packages, list) or not 1 <= len(packages) <= 8:
        raise ValueError('Request 1-8 Ubuntu package names.')
    if any(not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', name)
           for name in packages):
        raise ValueError('Only plain Ubuntu package names are accepted.')
    packages = list(dict.fromkeys(packages))
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
