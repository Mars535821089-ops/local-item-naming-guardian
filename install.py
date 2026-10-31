import pathlib,plistlib,shutil,subprocess,json,hashlib,os
P=pathlib.Path; src=P(__file__).parent; base=P.home()/'Library/Application Support/Mars Item Guardian'; base.mkdir(parents=True,exist_ok=True);base.chmod(0o700)
for name in ['guardian.py','launcher']:
 shutil.copy2(src/name,base/name)
app=P.home()/'Applications/系统维护-命名管家-核查新增项目并记录用途.app'
if app.exists(): raise SystemExit('Existing app: refusing overwrite')
exe=app/'Contents/MacOS/系统维护-命名管家-核查新增项目并记录用途';exe.parent.mkdir(parents=True)
shutil.copy2(src/exe.name,exe)
info={'CFBundleIdentifier':'com.mars.item-naming-guardian','CFBundleName':'系统维护-命名管家-核查新增项目并记录用途','CFBundleDisplayName':'系统维护-命名管家-核查新增项目并记录用途','CFBundleExecutable':exe.name,'CFBundlePackageType':'APPL','CFBundleVersion':'1','LSUIElement':True,'NSHighResolutionCapable':True}
(app/'Contents/Info.plist').write_bytes(plistlib.dumps(info))
subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(app)],check=True)
plist=P.home()/'Library/LaunchAgents/com.mars.item-naming-guardian.plist'
config={'Label':'com.mars.item-naming-guardian','Program':str(exe),'ProgramArguments':[str(exe)],'AssociatedBundleIdentifiers':['com.mars.item-naming-guardian'],'RunAtLoad':True,'ProcessType':'Interactive','KeepAlive':{'SuccessfulExit':False},'ThrottleInterval':60}
with open(plist,'xb') as f:f.write(plistlib.dumps(config))
plist.chmod(0o600)
subprocess.run(['/bin/launchctl','bootstrap','gui/'+str(os.getuid()),str(plist)],check=True)
print(app)
