#!/usr/bin/python3
"""Local, metadata-only observer. Never edits third-party software or permission stores."""
import argparse, shutil, collections, datetime, fcntl, hashlib, html, json, os, pathlib, plistlib, re, shlex, sqlite3, subprocess, tempfile, time
P=pathlib.Path
HOME=P.home()
BASE=HOME/'Library/Application Support/Mars Item Guardian'
LABEL='com.mars.item-naming-guardian'

def digest(b): return hashlib.sha256(b).hexdigest()
def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def atomic(p,b):
    p=P(p); p.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(dir=str(p.parent),prefix='.guardian-')
    try:
        with os.fdopen(fd,'wb') as f: f.write(b); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,p)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
def save(p,d): atomic(p,json.dumps(d,ensure_ascii=False,indent=2).encode())
def read(p,default=None):
    try: return json.loads(P(p).read_text())
    except FileNotFoundError: return default

def command(args):
    r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
    if r.returncode: raise RuntimeError('command failed: '+P(args[0]).name)
    return r.stdout

def missing_status(path):
    p=P(path)
    if len(p.parts)>2 and p.parts[1]=='Volumes' and not os.path.ismount('/Volumes/'+p.parts[2]): return '外置卷未挂载：保留'
    return '当前不可见：保留，不能据此判定已卸载'

def delta(old,new):
    return ([k for k in new if k not in old], [k for k in new if k in old and new[k]!=old[k]], [k for k in old if k not in new])

class Scan:
    def __init__(self): self.rows={}; self.coverage=[]
    def source(self,name,fn):
        before=len(self.rows)
        try:
            fn(); self.coverage.append({'source':name,'status':'ok','records_added':len(self.rows)-before})
        except Exception as e:
            self.coverage.append({'source':name,'status':'不可读取或扫描未完成','error_type':type(e).__name__})
    def add(self,kind,key,name,path='',**extra):
        self.rows[kind+':'+key]={'kind':kind,'name':name,'path':str(path),**extra}
    def launches(self,root):
        if not root.exists(): return
        for p in sorted(root.glob('*.plist')):
            try:
                b=p.read_bytes(); d=plistlib.loads(b); target=d.get('Program') or (d.get('ProgramArguments') or [''])[0]
                self.add('启动服务',str(p),d.get('Label',p.stem),p,executable=target,identity=digest(b),target_present=P(target).exists() if target else False)
            except Exception as e: self.coverage.append({'source':str(p),'status':'未解析','error_type':type(e).__name__})
    def apps(self):
        apps=set()
        for root in [P('/Applications'),HOME/'Applications',P('/System/Applications')]:
            if not root.exists(): continue
            for parent,dirs,files in os.walk(root):
                for n in list(dirs):
                    if n.endswith('.app'): apps.add(str(P(parent)/n)); dirs.remove(n)
                if len(P(parent).relative_to(root).parts)>3: dirs[:]=[]
        try:
            apps.update(x for x in command(['/usr/bin/mdfind','kMDItemContentType == "com.apple.application-bundle"']).decode().splitlines() if x.endswith('.app'))
        except Exception as e: self.coverage.append({'source':'Spotlight其他路径应用发现','status':'不可用','error_type':type(e).__name__})
        for a in sorted(apps):
            app=P(a)
            if not app.exists(): continue
            self.bundle(app)
            for sub in ['Contents/Library/LoginItems','Contents/Library/LaunchAgents','Contents/Library/LaunchDaemons','Contents/PlugIns','Contents/Library/SystemExtensions','Contents/XPCServices']:
                root=app/sub
                if not root.is_dir(): continue
                if sub.endswith(('LaunchAgents','LaunchDaemons')): self.source(str(root),lambda r=root:self.launches(r))
                else:
                    for child in root.iterdir():
                        if child.is_dir(): self.bundle(child,owner=a)
    def bundle(self,p,owner=''):
        info=p/'Contents/Info.plist'
        if not info.is_file(): return
        try:
            b=info.read_bytes(); d=plistlib.loads(b)
            self.add('软件组件' if owner else '应用',str(p),d.get('CFBundleDisplayName') or d.get('CFBundleName') or p.stem,p,bundle_id=d.get('CFBundleIdentifier',''),version=d.get('CFBundleShortVersionString',''),owner=owner,identity=digest(b))
            for i,s in enumerate(d.get('NSServices',[])):
                self.add('快捷服务',str(p)+':'+str(i),str(s.get('NSMenuItem',{}).get('default','服务')),p,owner=str(p),identity=digest(plistlib.dumps(s)))
        except Exception as e: self.coverage.append({'source':str(info),'status':'未解析','error_type':type(e).__name__})
    def btm(self):
        root=P('/private/var/db/com.apple.backgroundtaskmanagement')
        files=list(root.glob('BackgroundItems-v18*.btm'))
        if not files: raise RuntimeError('BTM format unavailable')
        for p in files:
            def one():
                objects=plistlib.loads(p.read_bytes())['$objects']
                def scalar(v):
                    if isinstance(v,plistlib.UID): v=objects[v.data]
                    if isinstance(v,(str,int,float,bool)): return None if v=='$null' else v
                    if isinstance(v,dict) and 'NS.relative' in v: return scalar(v['NS.relative'])
                    return None
                for i,d in enumerate(objects):
                    if isinstance(d,dict) and 'identifier' in d and 'name' in d:
                        row={k:scalar(d.get(k)) for k in ['identifier','name','url','executablePath','disposition','type','bundleIdentifier']}
                        key=p.name+':'+str(row['identifier'])+':'+str(row['url'])
                        self.add('后台注册',key,row.pop('name') or '',row.pop('url') or '',**row)
            self.source('后台数据库 '+p.name,one)
    def tcc(self,p):
        conn=sqlite3.connect(p.as_uri()+'?mode=ro',uri=True,timeout=1)
        try:
            for service,client,ctype,value in conn.execute('SELECT service,client,client_type,auth_value FROM access'):
                self.add('隐私权限',str(p)+':'+service+':'+client,client,client if ctype==1 else '',service=service,authorization=value)
        finally: conn.close()
    def firewall(self):
        raw=command(['/usr/libexec/ApplicationFirewall/socketfilterfw','--listapps']).decode()
        path=None
        for line in raw.splitlines():
            m=re.match(r'\d+\s*:\s*(.*)',line.strip())
            if m: path=m.group(1)
            elif path and ('connections' in line.lower()): self.add('防火墙',path,P(path).name,path,state=line.strip()); path=None
    def extensions(self):
        for line in command(['/usr/bin/systemextensionsctl','list']).decode().splitlines():
            if not line.strip(): continue
            self.add('系统扩展',digest(line.encode()),line.strip())
        raw=command(['/usr/bin/pluginkit','-m','-A','-D']).decode()
        for line in raw.splitlines():
            if line.strip(): self.add('应用扩展',digest(line.encode()),line.strip())
    def fingerprints(self):
        paths=[HOME/'Library/Preferences/com.apple.ncprefs.plist',HOME/'Library/Preferences/com.apple.symbolichotkeys.plist',P('/Library/Preferences/com.apple.networkextension.plist'),HOME/'Library/Group Containers/group.com.apple.controlcenter/Library/Preferences/group.com.apple.controlcenter.plist']
        for p in paths:
            def one(p=p):
                self.add('设置存储变更',str(p),p.stem,p,identity=digest(p.read_bytes()))
            self.source(str(p),one)
    def run(self):
        for root in [HOME/'Library/LaunchAgents',P('/Library/LaunchAgents'),P('/Library/LaunchDaemons')]: self.source(str(root),lambda r=root:self.launches(r))
        self.source('应用、内嵌服务与快捷服务',self.apps)
        self.source('后台注册',self.btm)
        for p in [P('/Library/Application Support/com.apple.TCC/TCC.db'),HOME/'Library/Application Support/com.apple.TCC/TCC.db']:
            self.source('隐私权限 '+str(p),lambda p=p:self.tcc(p))
        self.source('防火墙',self.firewall); self.source('系统与应用扩展',self.extensions)
        for root in [P('/Library/Audio/Plug-Ins/HAL'),HOME/'Library/Audio/Plug-Ins/HAL',P('/Library/PreferencePanes'),HOME/'Library/PreferencePanes',HOME/'Library/Services',P('/Library/Services')]:
            def scanroot(root=root):
                if root.is_dir():
                    for p in root.iterdir():
                        if p.is_dir(): self.bundle(p,owner=str(root))
            self.source(str(root),scanroot)
        self.fingerprints()
        self.coverage.append({'source':'用户受保护隐私库、部分通知与网络设置的逐项用途','status':'覆盖限制：不绕过系统保护；存储指纹只能发现变化，不能解释每个项目'})
        self.coverage.append({'source':'未被Spotlight索引的任意目录、离线外置卷、其他用户私有项目','status':'覆盖限制：不能保证发现；已登记路径持续追踪，不递归扫描个人文件'})
        return self

def reconcile(scan,old,rules):
    current=scan.rows; added,changed,missing=delta(old,current)
    events=[]
    for typ,keys in [('新增',added),('变化',changed),('当前不可见',missing)]:
        for k in keys:
            # Read permission changes are coverage events, not disappeared software.
            if typ=='当前不可见':
                category=old[k].get('kind','')
                failed=[c for c in scan.coverage if c['status']!='ok']
                if category in ['隐私权限','后台注册','设置存储变更'] and failed: continue
            r=current.get(k,old.get(k)); event={'kind':typ,'key':k,'name':r['name'],'path':r.get('path','')}
            rule=rules.get(k)
            if rule and r==rule['baseline']: event['resolution']='已核实：'+rule['purpose']
            elif typ=='当前不可见': event['resolution']=missing_status(r['path']) if r.get('path','').startswith('/') else '当前不可见：保留，可能是权限或扫描变化'
            else: event['resolution']='仅记录；用途或身份变化需核实'
            events.append(event)
    return events

def report(base,state,rules):
    esc=lambda x:html.escape(str(x))
    rows=[]
    for k,r in state['items'].items():
        rule=rules.get(k)
        purpose=rule['purpose'] if rule and r==rule['baseline'] else ('归属：'+r['owner'] if r.get('owner') else '尚无已核实用途；保留原项')
        rows.append('<tr>'+''.join('<td>'+esc(x)+'</td>' for x in [r['kind'],r['name'],purpose,r.get('path','')])+'</tr>')
    body='''<!doctype html><meta charset="utf-8"><title>本机项目命名管家</title><style>body{font:15px system-ui;margin:32px;background:#f5f6f8;color:#182332}td,th{padding:10px;text-align:left;border-bottom:1px solid #ddd;word-break:break-all}table{width:100%;border-collapse:collapse}input{padding:12px;width:80%}pre{white-space:pre-wrap}</style><h1>本机项目命名管家</h1><p>本地自动核查 · 不上传数据 · 不自动删除 · 不改第三方签名或权限</p>'''
    body+='<p>最近核查（UTC）：'+esc(state['at'])+'；项目 '+str(len(state['items']))+'</p>'
    body+='<details open><summary>最近变更</summary><pre>'+esc(json.dumps(list(read(base/'待核查.json',{}).values())[-30:],ensure_ascii=False,indent=2))+'</pre></details>'
    body+='<details><summary>覆盖限制与读取状态</summary><pre>'+esc(json.dumps(read(base/'coverage.json',[]),ensure_ascii=False,indent=2))+'</pre></details>'
    body+='<p><a href="待核查.json">累计变更记录</a> · <a href="coverage.json">覆盖范围与读取限制</a></p><input id="q" placeholder="搜索名称、用途、来源路径"><table><thead><tr><th>类别</th><th>名称</th><th>用途／归属</th><th>路径</th></tr></thead><tbody>'+''.join(rows)+'</tbody></table>'
    body+='''<script>document.getElementById('q').oninput=function(){for(const r of document.querySelectorAll('tbody tr'))r.hidden=!r.textContent.toLowerCase().includes(this.value.toLowerCase())}</script>'''
    atomic(base/'项目用途看板.html',body.encode())

def scan_once(base):
    base.mkdir(parents=True,exist_ok=True)
    with open(base/'scan.lock','a') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: return
        old=read(base/'state.json',{}); rules=read(base/'rules.json',{})
        scan=Scan().run(); state={'at':stamp(),'items':scan.rows}
        events=reconcile(scan,old.get('items',{}),rules) if old else []
        inbox=read(base/'待核查.json',{})
        for e in events:
            key=digest(json.dumps(e,sort_keys=True,ensure_ascii=False).encode())
            if key not in inbox: inbox[key]={'first_seen':stamp(),**e}
        save(base/'待核查.json',inbox); save(base/'coverage.json',scan.coverage)
        save(base/'state.json',state); report(base,state,rules)
        # Background completion evidence contains no project paths or command arguments.
        save(base/'health.json',{'last_success':state['at'],'items':len(scan.rows),'coverage_gaps':len([c for c in scan.coverage if c['status']!='ok'])})
        print(json.dumps({'items':len(scan.rows),'new_events':len(events),'pending':len(inbox),'at':state['at']}))

def validate_registration(d):
    for k in ['name','purpose','project','executable']:
        if not isinstance(d.get(k),str) or not d[k].strip(): raise ValueError('missing '+k)
    if not re.fullmatch(r'[^/\x00-\x1f-]{2,20}-[^/\x00-\x1f-]{2,40}-[^/\x00-\x1f-]{6,100}',d['name']): raise ValueError('name must be 类别-项目-具体用途')
    if len(d['purpose'])<12 or d['name'].split('-')[-1] in ['提供后台运行服务','执行后台服务程序']: raise ValueError('purpose too vague')
    if not P(d['project']).is_absolute() or not P(d['project']).is_dir(): raise ValueError('project missing')
    if not P(d['executable']).is_absolute() or not P(d['executable']).is_file() or not os.access(d['executable'],os.X_OK): raise ValueError('executable missing')
    if any('\n' in d[k] or '\r' in d[k] for k in ['project','executable']): raise ValueError('newline in path')
    if P(d['executable']).name.lower() in ['codex','claude']: raise ValueError('background AI CLI forbidden')
    if d.get('arguments'): raise ValueError('arguments not accepted: use a project-owned launcher, keep credentials in Keychain')

def register(base,manifest,apply):
    d=read(manifest); validate_registration(d)
    token=digest((d['project']+'\0'+d['name']).encode())[:16]; label='com.mars.named.'+token
    directory=base/'registered'/token; app=directory/(d['name']+'.app'); executable=app/'Contents/MacOS'/d['name']
    plist=HOME/'Library/LaunchAgents'/(label+'.plist')
    result={'label':label,'name':d['name'],'plist':str(plist),'action':'创建规范启动项；不会立即启动；下次登录生效','uninstall':'launchctl bootout gui/'+str(os.getuid())+'/'+label+' 后仅移除此 plist 和 registered/'+token}
    if apply:
        if plist.exists() or directory.exists(): raise ValueError('existing registration: refusing overwrite')
        directory.mkdir(parents=True,mode=0o700)
        executable.parent.mkdir(parents=True)
        shutil.copy2(base/'launcher',executable); executable.chmod(0o700)
        atomic(app/'Contents/Resources/original-executable',(d['executable']+'\n').encode())
        atomic(app/'Contents/Info.plist',plistlib.dumps({'CFBundleIdentifier':label,'CFBundleName':d['name'],'CFBundleDisplayName':d['name'],'CFBundleExecutable':d['name'],'CFBundlePackageType':'APPL','LSUIElement':True}))
        command(['/usr/bin/codesign','--force','--sign','-',str(app)])
        config={'Label':label,'AssociatedBundleIdentifiers':[label],'Program':str(executable),'ProgramArguments':[str(executable)],'RunAtLoad':True,'WorkingDirectory':d['project'],'ProcessType':'Background'}
        # Exclusive create: never replace an existing service.
        with open(plist,'xb') as f: os.chmod(plist,0o600); f.write(plistlib.dumps(config))
        save(directory/'registration.json',{**d,**result,'created_at':stamp()})
        # Bind explanatory rule to this exact configuration, never to a generic label alone.
        rules=read(base/'rules.json',{})
        row={'kind':'启动服务','name':label,'path':str(plist),'executable':str(executable),'identity':digest(plist.read_bytes()),'target_present':True}
        rules['启动服务:'+str(plist)]={'baseline':row,'purpose':d['name'],'evidence':'用户通过规范入口登记'}
        save(base/'rules.json',rules)
    print(json.dumps(result,ensure_ascii=False,indent=2))

def main():
    a=argparse.ArgumentParser(); a.add_argument('--base',type=P,default=BASE)
    sub=a.add_subparsers(dest='action',required=True); sub.add_parser('scan')
    r=sub.add_parser('register'); r.add_argument('manifest'); r.add_argument('--apply',action='store_true')
    args=a.parse_args()
    if args.action=='scan': scan_once(args.base)
    else: register(args.base,args.manifest,args.apply)
if __name__=='__main__': main()
