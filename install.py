"""Install once, or update Python logic without changing the signed UI identity."""
import argparse
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile

DEFAULT_BUILD=Path('/Volumes/Mars-私人服务器/内置盘写入统一管理/01-编译与构建/本机项目命名管家')
NAME='系统维护-命名管家-核查新增项目并记录用途'

def install(build,update=False):
    src=Path(__file__).parent;home=Path.home();base=home/'Library/Application Support/Mars Item Guardian'
    app=home/'Applications'/(NAME+'.app');plist=home/'Library/LaunchAgents/com.mars.item-naming-guardian.plist'
    if update:
        if not app.is_dir() or not plist.is_file():raise SystemExit('Install the application first')
    elif app.exists() or plist.exists():raise SystemExit('Existing app or agent: refusing overwrite; use --update-runtime')
    base.mkdir(parents=True,exist_ok=True);base.chmod(0o700)
    # Serialize against the active scanner; deploy dependency before the calling module.
    import fcntl
    with open(base/'scan.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        for name in ['normalizer.py','guardian.py']:
            fd,tmp=tempfile.mkstemp(dir=str(base))
            try:
                with os.fdopen(fd,'wb') as f:f.write((src/name).read_bytes());f.flush();os.fsync(f.fileno())
                os.replace(tmp,base/name)
            finally:
                if os.path.exists(tmp):os.unlink(tmp)
        if update:return
        shutil.copy2(build/'launcher',base/'launcher')
        exe=app/'Contents/MacOS'/NAME;exe.parent.mkdir(parents=True)
        shutil.copy2(build/NAME,exe)
        info={'CFBundleIdentifier':'com.mars.item-naming-guardian','CFBundleName':NAME,'CFBundleDisplayName':NAME,'CFBundleExecutable':NAME,'CFBundlePackageType':'APPL','CFBundleVersion':'2','LSUIElement':True,'NSHighResolutionCapable':True}
        (app/'Contents/Info.plist').write_bytes(plistlib.dumps(info))
        subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(app)],check=True)
        config={'Label':'com.mars.item-naming-guardian','Program':str(exe),'ProgramArguments':[str(exe)],'AssociatedBundleIdentifiers':['com.mars.item-naming-guardian'],'RunAtLoad':True,'ProcessType':'Interactive','KeepAlive':{'SuccessfulExit':False},'ThrottleInterval':60}
        with open(plist,'xb') as f:f.write(plistlib.dumps(config))
        plist.chmod(0o600)
        subprocess.run(['/bin/launchctl','bootstrap','gui/'+str(os.getuid()),str(plist)],check=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--build-dir',type=Path,default=DEFAULT_BUILD);parser.add_argument('--update-runtime',action='store_true');args=parser.parse_args()
    install(args.build_dir,args.update_runtime)
