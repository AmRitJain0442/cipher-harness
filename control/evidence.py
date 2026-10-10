"""Persistent per-session command reservations, results and searchable evidence."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import time
import uuid

ROOT=Path(__file__).resolve().parent


def fingerprint(command,environment='vm',cwd=''):
    # Preserve shell quoting: echo '$HOME' and echo "$HOME" are different commands.
    try:
        tokens=shlex.split(command,posix=False)
    except ValueError:
        tokens=[command]
    simple=not re.search(r'[;&|<>$`\n]',command)
    executable=Path(tokens[0]).name if tokens else ''
    if executable=='nmap' and simple:
        tokens=shlex.split(command,posix=True)
        expanded=[]
        for token in tokens:
            if re.fullmatch(r'-p[0-9,\-]+',token): expanded.extend(['-p',token[2:]])
            else: expanded.append(token)
        tokens=expanded
    portable=simple and executable in ('nmap','dig','host','whois','curl')
    file_flags=('-o','-O','--output','-K','--config','-T','--upload-file',
                '--cacert','--cert','--key','-b','--cookie','-c','--cookie-jar')
    if executable=='nmap': file_flags=('-oN','-oX','-oG','-oA')
    checked=[t for i,t in enumerate(tokens) if not (executable=='curl' and t=='-o' and i+1<len(tokens) and tokens[i+1]=='/dev/null')]
    if any(t==flag or (len(flag)==3 and t.startswith(flag)) for t in checked for flag in file_flags):
        portable=False
    if executable=='nmap' and simple:
        # Only independent flags can be reordered safely; retain all other argument order.
        independent={'-sV','-Pn','-n','-sC','-O','--open','-v','-vv'}
        flags=sorted(t for t in tokens[1:] if t in independent)
        rest=[t for t in tokens[1:] if t not in independent]
        tokens=['nmap',*rest,*flags]
    if portable:
        cwd=''
        # Loopback/Docker targets refer to different machines/namespaces.
        if executable in ('nmap','dig','host','whois') and not re.search(r'localhost|127\.|::1|172\.(1[6-9]|2\d|3[01])\.',command):
            environment='network'
    payload=json.dumps([tokens,environment,cwd],ensure_ascii=False)
    return hashlib.sha256(payload.encode()).hexdigest()


class Evidence:
    def __init__(self,path=None):
        self.path=Path(path) if path else Path(os.getenv('HARNESS_DATA_DIR', str(ROOT/'data')))/'evidence.sqlite3'
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with self.connect() as con:
            con.executescript('''PRAGMA journal_mode=WAL;
              CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY,job TEXT,fingerprint TEXT,
                command TEXT,environment TEXT,cwd TEXT,status TEXT,created REAL,updated REAL,
                output TEXT,uses INTEGER DEFAULT 0,UNIQUE(job,fingerprint));
              CREATE INDEX IF NOT EXISTS commands_job ON commands(job,updated);''')

    def connect(self):
        con=sqlite3.connect(self.path,timeout=10)
        con.row_factory=sqlite3.Row
        return con

    def reserve(self,job,command,environment='vm',cwd=''):
        record_id=uuid.uuid4().hex
        key=fingerprint(command,environment,cwd)
        now=time.time()
        with self.connect() as con:
            inserted=con.execute('INSERT OR IGNORE INTO commands(id,job,fingerprint,command,environment,cwd,status,created,updated,output) VALUES(?,?,?,?,?,?,?,?,?,?)',
                (record_id,job,key,self.redact(command),environment,cwd,'pending',now,now,'null')).rowcount
            row=dict(con.execute('SELECT * FROM commands WHERE job=? AND fingerprint=?',(job,key)).fetchone())
            if not inserted:
                con.execute('UPDATE commands SET uses=uses+1 WHERE id=?',(row['id'],))
                row['uses']+=1
        row['output']=json.loads(row['output'])
        return bool(inserted),row

    def finish(self,record_id,output,status='completed'):
        raw=json.dumps(output,ensure_ascii=False,default=str)
        raw=self.redact(raw)
        with self.connect() as con:
            con.execute('UPDATE commands SET status=?,output=?,updated=? WHERE id=?',
                (status,raw,time.time(),record_id))

    def redact(self,raw):
        for path in (Path.home()/'.config/orca/api-key',ROOT/'data/owner-key',Path(os.getenv('HARNESS_PENTAGI_PASSWORD_FILE', str(Path.home()/'security/pentagi-password')))):
            if path.exists():
                secret=path.read_text().strip()
                if secret: raw=raw.replace(secret,'[private credential]')
        for name in ('HARNESS_API_KEY','HARNESS_OWNER_KEY','HARNESS_PENTAGI_PASSWORD'):
            value=os.getenv(name,'')
            filename=os.getenv(name+'_FILE')
            if filename and Path(filename).is_file(): value=Path(filename).read_text().strip()
            if value: raw=raw.replace(value,'[private credential]')
        return raw

    def get(self,job,record_id):
        with self.connect() as con:
            row=con.execute('SELECT * FROM commands WHERE job=? AND id=?',(job,record_id)).fetchone()
        if not row: return None
        result=dict(row)
        result['output']=json.loads(result['output'])
        return result

    def find(self,job,command,environment='vm',cwd=''):
        with self.connect() as con:
            row=con.execute('SELECT id FROM commands WHERE job=? AND fingerprint=?',
                (job,fingerprint(command,environment,cwd))).fetchone()
        return self.get(job,row['id']) if row else None

    def search(self,job,query='',limit=10):
        # Literal substring search; SQL wildcard characters are not search operators.
        term='%'+query.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%'
        with self.connect() as con:
            rows=con.execute("SELECT * FROM commands WHERE job=? AND (command LIKE ? ESCAPE '\\' OR output LIKE ? ESCAPE '\\') ORDER BY updated DESC LIMIT ?",(job,term,term,limit)).fetchall()
        return [{**dict(row),'output':json.loads(row['output'])} for row in rows]

    def reuse(self,row):
        return {'cached':True,'executed_again':False,'evidence_id':row['id'],
                'reuse_count':row['uses'],
                'command':row['command'],'source_environment':row['environment'],
                'recorded_at':row['created'],'status':row['status'],'output':row['output'],
                'note':'Recorded observation, not a new execution. Inspect this evidence and choose a different next action.' if row['status']!='pending' else
                       'This command was reserved earlier, but no result is recorded. Execution may be incomplete or unknown. Do not silently restart it or assume success.'}

    def repeated(self,job):
        with self.connect() as con:
            return [dict(row) for row in con.execute('SELECT id,command,uses FROM commands WHERE job=? AND uses>=4',(job,))]

    def backfill(self,data_root):
        """Import retained native CAI tool transcripts and older T3MP3ST events."""
        data_root=Path(data_root)
        for artifact in data_root.glob('runs/*/cai-*/result.json'):
            try:
                data=json.loads(artifact.read_text())
                calls={}
                for item in data.get('conversation',[]):
                    if item.get('type')=='function_call':
                        calls[item['call_id']]=json.loads(item['arguments'])
                    elif item.get('type')=='function_call_output' and item.get('call_id') in calls:
                        args=calls[item['call_id']]
                        if not args.get('command'): continue
                        cwd=str((artifact.parent/args.get('working_directory','.')).resolve())
                        if self.find(artifact.parent.parent.name,args['command'],'vm',cwd): continue
                        execute,row=self.reserve(artifact.parent.parent.name,args['command'],'vm',cwd)
                        if execute:
                            self.finish(row['id'],item.get('output',''))
            except (OSError,ValueError,KeyError,TypeError):
                continue
        database=data_root/'control.sqlite3'
        if not database.exists(): return
        with sqlite3.connect(database) as con:
            actions={}
            for job,kind,payload in con.execute("SELECT job,kind,payload FROM events WHERE title='t3mp3st' AND kind IN ('action','result') ORDER BY id"):
                try: value=json.loads(payload)
                except ValueError: continue
                if kind=='action':
                    actions[job]=value
                    continue
                args=actions.get(job,{})
                if args.get('operation')!='command' or not args.get('command') or value.get('cached'): continue
                if self.find(job,args['command'],'vm',str(Path(os.getenv('HARNESS_SECURITY_DIR', str(Path.home()/'security')))/'T3MP3ST')): continue
                execute,row=self.reserve(job,args['command'],'vm',str(Path(os.getenv('HARNESS_SECURITY_DIR', str(Path.home()/'security')))/'T3MP3ST'))
                if execute:
                    self.finish(row['id'],value,'failed' if 'error' in value or value.get('success') is False else 'completed')
