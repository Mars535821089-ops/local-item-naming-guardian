"""Evidence-bound user LaunchAgent naming. No daemon, permission DB, or app edits."""
import copy
import ctypes
import datetime
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import tempfile
import time
import uuid

class Protected(ValueError):
    pass

def sha(data):
    return hashlib.sha256(data).hexdigest()

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sync_directory(path):
    fd=os.open(str(path),os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

def write_private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(dir=str(path.parent), prefix='.naming-')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(temp, path);sync_directory(path.parent)
    finally:
        if os.path.exists(temp): os.unlink(temp)

def save(path, value):
    write_private(path, json.dumps(value, ensure_ascii=False, indent=2).encode())

def read(path, default):
    if not path.exists(): return default
    if path.is_symlink(): raise Protected('symlink state')
    return json.loads(path.read_text())

def store(base):
    root = Path(base)/'normalization'
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or root.stat().st_uid != os.getuid(): raise Protected('unsafe state directory')
    root.chmod(0o700)
    return root

def load_rules(base):
    return read(store(base)/'rules.json', [])

def checked_config(path, home):
    path = Path(path); home = Path(home)
    if path.parent != home/'Library/LaunchAgents' or path.parent.resolve() != path.parent:
        raise Protected('outside owned user LaunchAgents')
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1 or st.st_mode & 0o022:
        raise Protected('config must be owned, regular, non-shared and not group writable')
    raw = path.read_bytes(); d = plistlib.loads(raw)
    if path.stat().st_ino != st.st_ino: raise Protected('config replaced during read')
    if not isinstance(d.get('Label'), str) or not isinstance(d.get('ProgramArguments'), list) or not d['ProgramArguments']:
        raise Protected('unsupported launch configuration')
    if not all(isinstance(x, str) for x in d['ProgramArguments']): raise Protected('invalid arguments')
    # These launchd features alter argv handling, bundle resolution, or code requirements.
    if any(k in d for k in ['BundleProgram', 'RootDirectory', 'UserName', 'GroupName', 'MachServices', 'SMAuthorizedClients']):
        raise Protected('unsupported security or bundle identity semantics')
    return raw, d, st

def target_of(d):
    return d.get('Program') or d['ProgramArguments'][0]

def behavioral_hash(d):
    d = copy.deepcopy(d)
    for k in ['Program', 'AssociatedBundleIdentifiers']: d.pop(k, None)
    d['ProgramArguments'][0] = '<entry>'
    return sha(plistlib.dumps(d, sort_keys=True))

def file_pin(path):
    p = Path(path)
    if not p.is_absolute() or not p.is_file(): raise Protected('source or executable is unavailable')
    return {'path':str(p), 'sha256':sha(p.read_bytes())}

def metadata(d):
    return {k:copy.deepcopy(d[k]) for k in ['Program','AssociatedBundleIdentifiers'] if k in d} | {'argv0':d['ProgramArguments'][0]}

def validate_name(name):
    if not re.fullmatch(r'[^/\x00-\x1f-]{2,20}-[^/\x00-\x1f-]{2,40}-[^/\x00-\x1f-]{6,100}', name):
        raise Protected('use 类别-项目-具体用途')

def enroll_rule(base, plist, name, sources, home=None, original_target=None):
    home = Path(home or Path.home()); plist = Path(plist); validate_name(name)
    raw, d, _ = checked_config(plist, home)
    root = store(base)
    with open(root/'rules.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        rules = load_rules(base)
        if any(r['label']==d['Label'] or r['plist']==str(plist) for r in rules): raise Protected('already enrolled; original provenance is immutable')
        entry = target_of(d)
        target = original_target or entry
        if original_target:
            # Only adopt an existing named wrapper with its own explicit target resource.
            app = Path(entry).resolve().parent.parent.parent
            if app.parent != home/'Library/Application Support/Mars Background Items' and app.parent.parent != Path(base).resolve()/'registered': raise Protected('unapproved legacy wrapper root')
            info = plistlib.loads((app/'Contents/Info.plist').read_bytes())
            if info.get('CFBundleExecutable') != Path(entry).name or Path(entry).name != name: raise Protected('legacy wrapper identity mismatch')
            if (app/'Contents/Resources/original-executable').read_text().strip() != target: raise Protected('legacy target mismatch')
            subprocess.run(['/usr/bin/codesign','--verify','--strict',str(app)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        if d['ProgramArguments'][0] not in [target,entry]: raise Protected('custom argv0 would change behavior')
        if Path(target).name.lower() in ['codex','claude']: raise Protected('background AI CLI prohibited')
        if not Path(target).is_absolute() or '\n' in target or '\r' in target: raise Protected('unsafe target')
        if not sources: raise Protected('explicit source evidence is required')
        pins = [file_pin(p) for p in sources]
        executable = file_pin(target)
        if Path(target).resolve()==Path(entry).resolve() and original_target: raise Protected('self reference')
        token = sha((d['Label']+'\0'+name+'\0'+target).encode())[:20]
        wrapper = Path(entry) if original_target else root/'wrappers'/token/(name+'.app')/'Contents/MacOS'/name
        rule = {'version':1,'label':d['Label'],'plist':str(plist),'name':name,'target':target,'target_pin':executable,'source_pins':pins,'behavior_sha256':behavioral_hash(d),'approved_entry':entry,'wrapper':str(wrapper),'original_metadata':metadata(d),'enabled':True,'approved_at':now()}
        # A target cannot be any naming wrapper, not only its own current path.
        if 'Mars Background Items' in Path(target).parts or root in Path(target).parents: raise Protected('wrapper cannot target another wrapper')
        rules.append(rule); save(root/'rules.json',rules)
        return rule

def run_checked(args):
    result = subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
    if result.returncode: raise Protected('wrapper verification or signing failed')
    return result.stdout

def ensure_wrapper(base, rule):
    exe = Path(rule['wrapper']); app = exe.parent.parent.parent
    if app.exists():
        if app.is_symlink() or exe.is_symlink(): raise Protected('wrapper symlink')
        target = (app/'Contents/Resources/original-executable').read_text().strip()
        if target != rule['target'] or Path(target).resolve()==exe.resolve(): raise Protected('wrapper provenance changed or self reference')
        info = plistlib.loads((app/'Contents/Info.plist').read_bytes())
        if info.get('CFBundleExecutable') != rule['name']: raise Protected('wrapper metadata changed')
        run_checked(['/usr/bin/codesign','--verify','--strict',str(app)])
        return register_wrapper(base,app)
    launcher = Path(base)/'launcher'
    if not launcher.is_file(): raise Protected('launcher missing')
    app.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    temp = Path(tempfile.mkdtemp(dir=str(app.parent),prefix='.build-'))
    try:
        staged = temp/app.name
        binary = staged/'Contents/MacOS'/rule['name']; binary.parent.mkdir(parents=True)
        shutil.copy2(launcher,binary); binary.chmod(0o700)
        write_private(staged/'Contents/Resources/original-executable',(rule['target']+'\n').encode())
        identifier = 'com.mars.purpose.'+app.parent.name
        write_private(staged/'Contents/Info.plist',plistlib.dumps({'CFBundleIdentifier':identifier,'CFBundleName':rule['name'],'CFBundleDisplayName':rule['name'],'CFBundleExecutable':rule['name'],'CFBundlePackageType':'APPL','LSUIElement':True}))
        run_checked(['/usr/bin/codesign','--force','--sign','-',str(staged)])
        run_checked(['/usr/bin/codesign','--verify','--strict',str(staged)])
        os.rename(staged,app)
    finally:
        shutil.rmtree(temp)
    return register_wrapper(base,app)

def register_wrapper(base,app):
    marker=store(base)/'launchservices'/(sha(str(app).encode())+'.json')
    identity=sha((app/'Contents/Info.plist').read_bytes())
    if read(marker,{}).get('identity')==identity and read(marker,{}).get('version')==2:return False
    run_checked(['/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister','-f',str(app)])
    save(marker,{'identity':identity,'at':now(),'version':2});return True

def verify_identity(rule, d):
    if d['Label'] != rule['label'] or behavioral_hash(d) != rule['behavior_sha256']: raise Protected('launch behavior changed; evidence rule no longer matches')
    if target_of(d) not in [rule['target'],rule['approved_entry'],rule['wrapper']]: raise Protected('entry identity changed')
    if d['ProgramArguments'][0] not in [rule['target'],rule['approved_entry'],rule['wrapper']]: raise Protected('custom argv0')
    if file_pin(rule['target']) != rule['target_pin']: raise Protected('executable changed or unavailable')
    for pin in rule['source_pins']:
        if file_pin(pin['path']) != pin: raise Protected('source changed or unavailable')

def service_state(label):
    # Do not dump launchctl environment or arguments into any journal.
    r = subprocess.run(['/bin/launchctl','print','gui/'+str(os.getuid())+'/'+label],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
    if r.returncode: return {'loaded':False}
    m = re.search(rb'^\s*pid = (\d+)',r.stdout,re.M)
    return {'loaded':True,'pid':int(m.group(1)) if m else None}

def disabled_state(label):
    r = subprocess.run(['/bin/launchctl','print-disabled','gui/'+str(os.getuid())],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
    if r.returncode: return None
    m = re.search(rb'"'+re.escape(label.encode())+rb'"\s*=>\s*(true|false)',r.stdout)
    return m.group(1).decode() if m else 'unspecified'

def refresh_display(rule, before):
    # Legacy load refreshes BTM registration for an already loaded job without enable/force flags.
    if not before.get('loaded'): return {'attempted':False}
    if plistlib.loads(Path(rule['plist']).read_bytes()).get('Disabled'):return {'attempted':False}
    disabled = disabled_state(rule['label'])
    if disabled in [None,'true']: return {'attempted':False}
    current = service_state(rule['label'])
    if current != before: return {'attempted':False,'reason':'runtime changed'}
    r = subprocess.run(['/bin/launchctl','load',rule['plist']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
    after = service_state(rule['label'])
    return {'attempted':True,'exit_code':r.returncode,'same_pid':before.get('pid')==after.get('pid'),'disabled_unchanged':disabled==disabled_state(rule['label'])}

def exclusive_rename(source, target):
    libc=ctypes.CDLL(None,use_errno=True)
    libc.renamex_np.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_uint32]
    libc.renamex_np.restype=ctypes.c_int
    if libc.renamex_np(os.fsencode(source),os.fsencode(target),4):
        error=ctypes.get_errno()
        raise OSError(error,os.strerror(error))

def recover_config(path):
    recovery=path.parent/'.naming-recovery'
    if not recovery.exists():return
    if recovery.is_symlink() or recovery.stat().st_uid!=os.getuid():raise Protected('unsafe recovery directory')
    for marker in recovery.glob(path.name+'.*.json'):
        record=read(marker,{})
        if not isinstance(record,dict) or record.get('path')!=str(path):raise Protected('invalid recovery metadata')
        claim=Path(record.get('claim',''))
        if claim.parent!=recovery or not claim.name.startswith(path.name+'.') or claim.is_symlink():raise Protected('invalid recovery original')
        if not claim.exists():marker.unlink();continue
        if sha(claim.read_bytes())!=record.get('original_sha256'):raise Protected('recovery original changed')
        if not os.path.lexists(path):
            try:exclusive_rename(claim,path)
            except FileExistsError:continue
            marker.unlink()
        elif path.is_file() and sha(path.read_bytes())==record.get('expected_sha256'):
            claim.unlink();marker.unlink()

def commit_config(path, raw, st, desired):
    """Claim and verify the original inode; exclusively commit without replacing an updater."""
    fd,temp=tempfile.mkstemp(dir=str(path.parent),prefix='.naming-')
    # A recovery original is moved, never copied with credentials into a JSON journal.
    recovery=path.parent/'.naming-recovery'
    recovery.mkdir(mode=0o700,exist_ok=True)
    if recovery.is_symlink() or recovery.stat().st_uid!=os.getuid():raise Protected('unsafe recovery directory')
    recovery.chmod(0o700)
    claim=recovery/(path.name+'.'+uuid.uuid4().hex+'.original')
    claimed=False;marker=claim.with_suffix('.json')
    try:
        with os.fdopen(fd,'wb') as output:
            output.write(plistlib.dumps(desired,fmt=plistlib.FMT_XML));output.flush();os.fsync(output.fileno())
            source=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW)
            try:
                if os.fstat(source).st_ino!=st.st_ino or os.read(source,len(raw)+1)!=raw:raise Protected('config changed at commit')
                libc=ctypes.CDLL(None,use_errno=True)
                libc.fcopyfile.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32]
                libc.fcopyfile.restype=ctypes.c_int
                if libc.fcopyfile(source,output.fileno(),None,7)!=0:raise Protected('cannot preserve original file metadata')
            finally:os.close(source)
        os.utime(temp,None)
        save(marker,{'path':str(path),'claim':str(claim),'original_sha256':sha(raw),'expected_sha256':sha(Path(temp).read_bytes())})
        exclusive_rename(path,claim);claimed=True;sync_directory(recovery);sync_directory(path.parent)
        if claim.lstat().st_ino!=st.st_ino or claim.read_bytes()!=raw:raise Protected('claimed config changed concurrently')
        # RENAME_EXCL cannot overwrite a configuration another process just installed.
        exclusive_rename(temp,path);sync_directory(path.parent)
        claim.unlink();claimed=False;sync_directory(recovery)
    except OSError as error:
        if error.errno==errno.EEXIST:raise Protected('updater created a new config; retained recovery original') from error
        raise
    finally:
        if claimed:
            try:exclusive_rename(claim,path)
            except OSError:pass  # New config wins. Original retained privately for manual recovery.
        if not claim.exists() and marker.exists():marker.unlink()
        if os.path.exists(temp):os.unlink(temp)

def normalize(base, home=None, refresh=True, before_commit=None, settle_seconds=2, refresh_labels=()):
    home = Path(home or Path.home()); root = store(base); results=[]
    with open(root/'apply.lock','a') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: return []
        for rule in load_rules(base):
            result = {'label':rule['label'],'name':rule['name'],'at':now()}
            if not rule.get('enabled'): continue
            try:
                path = Path(rule['plist']); recover_config(path); raw,d,st=checked_config(path,home)
                if time.time()-st.st_mtime < settle_seconds: raise Protected('installation still changing; retry on next scan')
                verify_identity(rule,d); newly_registered=ensure_wrapper(base,rule)
                desired = copy.deepcopy(d)
                desired['Program']=rule['wrapper'];desired['ProgramArguments'][0]=rule['wrapper']
                app=Path(rule['wrapper']).parent.parent.parent
                identifier=plistlib.loads((app/'Contents/Info.plist').read_bytes())['CFBundleIdentifier']
                desired['AssociatedBundleIdentifiers']=[identifier]
                if desired==d:
                    result['status']='already_normalized'
                    if refresh and (newly_registered or rule['label'] in refresh_labels):
                        marker=root/'display-refresh'/(sha(rule['label'].encode())+'.json')
                        last=read(marker,{}).get('last_attempt',0)
                        if time.time()-last>=300:
                            if path.lstat().st_ino==st.st_ino and path.read_bytes()==raw:os.utime(path,None)
                            runtime=service_state(rule['label'])
                            if runtime.get('loaded'):
                                app=Path(rule['wrapper']).parent.parent.parent
                                run_checked(['/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister','-f',str(app)])
                                result['display_refresh']=refresh_display(rule,runtime)
                                save(marker,{'last_attempt':time.time(),'outcome':result['display_refresh']})
                    results.append(result);continue
                # No credentials, arguments, or environment values are copied to transaction logs.
                transaction={'id':uuid.uuid4().hex,'label':rule['label'],'plist':str(path),'at':now(),'before_sha256':sha(raw),'original_metadata':metadata(d),'wrapper':rule['wrapper'],'status':'prepared'}
                journal=root/'transactions'/(transaction['id']+'.json');save(journal,transaction)
                before=service_state(rule['label']) if refresh else {'loaded':False}
                if before_commit: before_commit()
                check,latest,latest_st=checked_config(path,home)
                if check!=raw or latest_st.st_ino!=st.st_ino: raise Protected('config changed concurrently')
                verify_identity(rule,latest)
                commit_config(path,raw,st,desired)
                if plistlib.loads(path.read_bytes())!=desired: raise Protected('post-write verification failed')
                transaction['status']='applied';transaction['after_sha256']=sha(path.read_bytes());save(journal,transaction)
                result['status']='applied';result['transaction']=transaction['id']
                try:
                    result['display_refresh']=refresh_display(rule,before) if refresh and before.get('loaded') else {'attempted':False}
                except (OSError,subprocess.SubprocessError):
                    result['display_refresh']={'attempted':True,'verified':False,'reason':'runtime refresh unavailable; config retained'}
            except (OSError,ValueError,KeyError,subprocess.SubprocessError) as e:
                result['status']='protected';result['reason']=str(e) if isinstance(e,Protected) else type(e).__name__
            results.append(result)
        save(root/'last-run.json',{'at':now(),'results':results})
    return results

def restore(base, label, home=None):
    root=store(base);home=Path(home or Path.home())
    with open(root/'apply.lock','a') as lock, open(root/'rules.lock','a') as rules_lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        fcntl.flock(rules_lock,fcntl.LOCK_EX)
        rules=load_rules(base);rule=next(r for r in rules if r['label']==label)
        path=Path(rule['plist']);recover_config(path);raw,d,st=checked_config(path,home)
        if target_of(d)!=rule['wrapper']: raise Protected('not the managed wrapper; refusing restore')
        m=rule['original_metadata']
        for key in ['Program','AssociatedBundleIdentifiers']:
            if key in m:d[key]=m[key]
            else:d.pop(key,None)
        d['ProgramArguments'][0]=m['argv0']
        if path.read_bytes()!=raw: raise Protected('config changed concurrently')
        commit_config(path,raw,st,d)
        rule['enabled']=False;save(root/'rules.json',rules)
        return {'label':label,'status':'restored_and_automatic_rule_disabled'}

def process_requests(base, home=None):
    """All local tools can drop a purpose manifest; only owned user agents qualify."""
    root=store(base);inbox=root/'requests';inbox.mkdir(exist_ok=True,mode=0o700)
    for path in sorted(inbox.glob('*.json')):
        receipt=root/'request-results'/path.name
        if receipt.exists(): continue
        result={'request':path.name,'at':now()}
        try:
            st=path.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077: raise Protected('purpose requests must be owned regular files with mode 0600')
            d=json.loads(path.read_text())
            if not isinstance(d,dict):raise Protected('request must be a JSON object')
            if not all(isinstance(d.get(k),str) for k in ['plist','name','purpose']):raise Protected('plist, name and purpose must be strings')
            if not isinstance(d.get('purpose'),str) or len(d['purpose'])<12: raise Protected('concrete purpose statement required')
            if not isinstance(d.get('sources'),list) or not all(isinstance(x,str) for x in d['sources']):raise Protected('explicit source paths required')
            rule=enroll_rule(base,Path(d['plist']),d['name'],d['sources'],home=home)
            result.update(status='enrolled',label=rule['label'],name=rule['name'])
        except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as e:
            result.update(status='protected',reason=str(e) if isinstance(e,Protected) else type(e).__name__)
        save(receipt,result)
