"""Install model-requested Ubuntu packages through the trusted supervisor."""
import re
import subprocess


def install_packages(packages):
    if not isinstance(packages,list) or len(packages)>8:
        raise ValueError('At most eight Ubuntu packages per cycle are supported.')
    if any(not isinstance(p,str) or not re.fullmatch(r'[a-z][a-z0-9+.-]{0,79}',p) for p in packages):
        raise ValueError('Use plain Ubuntu package names, without shell commands or options.')
    packages=sorted(set(packages))
    if not packages:
        return {'requested':[], 'installed':[], 'output':''}
    missing=[]
    for package in packages:
        installed=subprocess.run(['dpkg-query','-W','-f=${Status}',package],capture_output=True,text=True)
        if installed.returncode==0 and installed.stdout=='install ok installed':
            continue
        known=subprocess.run(['apt-cache','show',package],capture_output=True,text=True)
        if known.returncode or not known.stdout.strip():
            raise ValueError('Package is absent from configured Ubuntu repositories: '+package)
        missing.append(package)
    if not missing:
        return {'requested':packages,'installed':[],'output':'Already installed.'}
    result=subprocess.run(['sudo','-n','env','DEBIAN_FRONTEND=noninteractive','apt-get','install',
                           '-y','--no-install-recommends','--',*missing],capture_output=True,text=True,timeout=300)
    output=(result.stdout+result.stderr)[-6000:]
    if result.returncode:
        raise RuntimeError('Package provisioning failed: '+output)
    return {'requested':packages,'installed':missing,'output':output}
