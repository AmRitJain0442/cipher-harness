"""Install checksum-verified official ProjectDiscovery Linux release binaries."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import urllib.request
import zipfile


def download(url):
    request=urllib.request.Request(url,headers={'User-Agent':'cipher-harness-tool-installer'})
    with urllib.request.urlopen(request,timeout=90) as response:
        return response.read()


def install(tool, prefix, architecture):
    release=json.loads(download('https://api.github.com/repos/projectdiscovery/'+tool+'/releases/latest'))
    version=release['tag_name'].removeprefix('v')
    filename=f'{tool}_{version}_linux_{architecture}.zip'
    assets={asset['name']:asset['browser_download_url'] for asset in release['assets']}
    checksums=next(name for name in assets if name.endswith('checksums.txt'))
    expected=None
    for line in download(assets[checksums]).decode().splitlines():
        fields=line.split()
        if len(fields)==2 and fields[1].lstrip('*')==filename:
            expected=fields[0]
            break
    if not expected:
        raise RuntimeError('Official checksum missing for '+filename)
    archive=download(assets[filename])
    digest=hashlib.sha256(archive).hexdigest()
    if digest!=expected:
        raise RuntimeError('Release archive checksum mismatch for '+tool)
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        binary=bundle.read(tool)
    prefix.mkdir(parents=True,exist_ok=True)
    temporary=prefix/(tool+'.download')
    temporary.write_bytes(binary)
    temporary.chmod(0o755)
    temporary.replace(prefix/tool)
    return {'tool':tool,'version':version,'archive_sha256':digest,
            'release':release['html_url'],'path':str(prefix/tool)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix',type=Path,default=Path('/usr/local/bin'))
    args=parser.parse_args()
    machine=platform.machine()
    architecture={'x86_64':'amd64','aarch64':'arm64'}.get(machine)
    if platform.system()!='Linux' or not architecture:
        raise SystemExit('Installer supports Linux amd64/arm64 only.')
    results=[install(tool,args.prefix,architecture) for tool in ('httpx','nuclei')]
    print(json.dumps(results,indent=2))


if __name__=='__main__':
    main()
