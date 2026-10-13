import argparse, collections, hashlib, json, os, pathlib, re, subprocess, sys

parser=argparse.ArgumentParser(description='Read-only Git source/history risk audit.')
parser.add_argument('repository',type=pathlib.Path)
parser.add_argument('--output',type=pathlib.Path,required=True)
args=parser.parse_args()
REPO=args.repository.resolve()
OUT=args.output.resolve()
if not REPO.is_dir() or OUT==REPO or OUT.is_relative_to(REPO):
    raise ValueError('Output must be a new directory outside repository')
OUT.mkdir(parents=True,exist_ok=False)
os.environ.update(GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0',GIT_NO_LAZY_FETCH='1')
GIT=['git','--no-optional-locks','-c','core.fsmonitor=false','-c','core.hooksPath=NUL']
def git(*args, binary=False):
    r = subprocess.run(GIT+['-C',str(REPO),*args], check=True, capture_output=True)
    return r.stdout if binary else r.stdout.decode('utf-8', 'replace')

tracked = git('ls-files', '-z').split('\0')[:-1]
untracked = git('ls-files', '--others', '--exclude-standard', '-z').split('\0')[:-1]
ignored = git('ls-files', '--others', '--ignored', '--exclude-standard', '-z').split('\0')[:-1]
refs = git('for-each-ref', '--format=%(refname) %(objectname)').splitlines()
objects = git('rev-list', '--objects', '--all').splitlines()
object_paths = dict(line.split(' ', 1) if ' ' in line else (line, '') for line in objects)
batch = subprocess.run(GIT+['-C',str(REPO),'cat-file','--batch-check=%(objectname) %(objecttype) %(objectsize)'], input=('\n'.join(object_paths)+'\n').encode(), capture_output=True, check=True)
blobs = []
for line in batch.stdout.decode().splitlines():
    oid, kind, size = line.split()
    if kind == 'blob': blobs.append({'oid': oid, 'size': int(size), 'path': object_paths[oid]})

risk_re = re.compile(r'(^|/)(?:output|outputs|renders|logs|cache|\.cache|\.venv|venv|env|node_modules|\.next|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|dist|build|\.claude|\.codex|backup)(/|$)|\.(?:mp4|mov|avi|mkv|webm|db|db-shm|db-wal|sqlite|sqlite3|safetensors|ckpt|pt|pth|bin|gguf|onnx|pyc|log)$|(^|/)\.env(\.|$)|(?:credential|service.account|private.key)', re.I)
disk_files=[]
skipped=[]
for root, dirs, files in os.walk(REPO, followlinks=False):
    for d in list(dirs):
        p=pathlib.Path(root)/d
        if p.is_symlink() or p.is_junction():
            skipped.append(str(p.relative_to(REPO))); dirs.remove(d)
    for name in files:
        p=pathlib.Path(root)/name
        try: disk_files.append({'path':p.relative_to(REPO).as_posix(),'size':p.stat().st_size})
        except OSError: skipped.append(str(p.relative_to(REPO)))
summary=collections.defaultdict(lambda: {'files':0,'bytes':0})
for f in disk_files:
    key=f['path'].split('/')[0]; summary[key]['files']+=1; summary[key]['bytes']+=f['size']

# Only record rule, location and a digest; never persist matching credential values.
patterns = {
 'provider-token': re.compile(rb'(?i)(?:sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|hf_[A-Za-z0-9]{25,}|AKIA[0-9A-Z]{16})'),
 'private-key': re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
 'credential-assignment': re.compile(rb'''(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret|password|passwd|bearer)\s*["']?\s*[:=]\s*["']([^\r\n"']{6,})["']'''),
 'url-credential': re.compile(rb'(?i)(?:https?|postgres(?:ql)?|mysql|mongodb)://[^\s/:]+:[^\s/@]+@'),
 'jwt': re.compile(rb'eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}'),
}
findings=[]
def scan(data, location, oid=None):
    if b'\0' in data[:8192]: return
    for rule, pat in patterns.items():
        for m in pat.finditer(data):
            findings.append({'rule':rule,'location':location,'line':data.count(b'\n',0,m.start())+1,'oid':oid})
proc=subprocess.Popen(GIT+['-C',str(REPO),'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
for b in blobs:
    if b['size'] > 10*1024*1024: continue
    proc.stdin.write((b['oid']+'\n').encode()); proc.stdin.flush()
    header=proc.stdout.readline(); size=int(header.split()[2]); data=proc.stdout.read(size); proc.stdout.read(1)
    scan(data,'history:'+b['path'],b['oid'])
proc.stdin.close();proc.wait()
for name in tracked+untracked:
    p=REPO/name
    if not p.is_symlink() and p.is_file() and p.stat().st_size <= 10*1024*1024: scan(p.read_bytes(),'working:'+name)

report={'repository':str(REPO),'refs':refs,'tracked':tracked,'untracked':untracked,'ignored':ignored,'disk_summary':dict(summary),'disk_top':sorted(disk_files,key=lambda x:x['size'],reverse=True)[:40],'skipped_links':skipped,'blob_count':len(blobs),'blob_bytes':sum(b['size'] for b in blobs),'largest_blobs':sorted(blobs,key=lambda x:x['size'],reverse=True)[:40],'risky_tracked':[p for p in tracked if risk_re.search(p)],'risky_history':[b for b in blobs if risk_re.search(b['path'])],'secret_findings':findings}
(OUT/'audit.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps({k:report[k] for k in ['refs','untracked','disk_summary','disk_top','skipped_links','blob_count','blob_bytes','largest_blobs','risky_tracked','secret_findings']},indent=2))
print('Tracked:',len(tracked),'Ignored:',len(ignored),'Risky historical blobs:',len(report['risky_history']))
