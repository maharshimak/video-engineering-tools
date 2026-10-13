import argparse, collections, hashlib, json, os, pathlib, re, sys
parser=argparse.ArgumentParser(description='Inventory an explicitly selected source copy without following links.')
parser.add_argument('root',type=pathlib.Path)
parser.add_argument('--output',type=pathlib.Path,required=True)
args=parser.parse_args()
R=args.root.resolve()
W=args.output.resolve()
if not R.is_dir() or W==R or W.is_relative_to(R):
    raise ValueError('Output must be a new directory outside input tree')
W.mkdir(parents=True,exist_ok=False)
files=[]; links=[]; errors=[]; dirs=[]
for root,subdirs,names in os.walk(R,followlinks=False):
    for d in list(subdirs):
        p=pathlib.Path(root)/d
        if p==R/'.git': subdirs.remove(d); continue
        if p.is_symlink() or p.is_junction():
            links.append(p.relative_to(R).as_posix());subdirs.remove(d)
        else: dirs.append(p.relative_to(R).as_posix())
    for name in names:
        p=pathlib.Path(root)/name
        rel=p.relative_to(R).as_posix()
        if rel=='.git': continue
        if p.is_symlink(): links.append(rel);continue
        try:
            s=p.stat()
            files.append({'path':rel,'size':s.st_size,'mtime_ns':s.st_mtime_ns})
        except OSError as e: errors.append({'path':rel,'error':type(e).__name__})
summary=collections.defaultdict(lambda:{'files':0,'bytes':0})
for f in files:
    k=f['path'].split('/')[0];summary[k]['files']+=1;summary[k]['bytes']+=f['size']
suspect_names=[]
for f in files:
    if re.search(r'(^|/)(\.env(?:\..*)?|\.npmrc|\.netrc|credentials[^/]*|service[-_]account[^/]*|id_rsa|id_ed25519|cookies[^/]*|tokens?\.json)$|\.(pem|key|pfx|p12)$',f['path'],re.I):
        suspect_names.append(f)
out={'root':str(R),'files':files,'directories':dirs,'links':links,'errors':errors,'summary':dict(summary),'credential_filename_candidates':suspect_names}
(W/'inventory.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
print(json.dumps({'file_count':len(files),'bytes':sum(f['size'] for f in files),'summary':dict(summary),'largest':sorted(files,key=lambda f:f['size'],reverse=True)[:12],'credential_filename_candidates':suspect_names,'links':links,'errors':errors},indent=2))
