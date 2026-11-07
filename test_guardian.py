import unittest,tempfile,pathlib,unittest.mock as mock
import guardian as g
class Safety(unittest.TestCase):
 def test_offline_volume_never_obsolete(self):
  with mock.patch('os.path.ismount',return_value=False): self.assertIn('保留',g.missing_status('/Volumes/offline/project/run'))
 def test_permission_gap_suppresses_false_removal(self):
  scan=g.Scan();scan.coverage=[{'source':'privacy','status':'不可读取'}]
  self.assertEqual(g.reconcile(scan,{'x':{'kind':'隐私权限','name':'x','path':'/x'}},{}),[])
 def test_permission_baseline_is_per_database(self):
  events=[{'kind':'新增','key':'隐私权限:/system/db:service:app'},{'kind':'新增','key':'隐私权限:/user/db:service:app'}]
  self.assertEqual(g.permission_baselines(events,[{'source':'隐私权限 /user/db','status':'不可读取'}]),[events[1]])
 def test_identity_change_does_not_inherit_purpose(self):
  a={'name':'node','path':'/x','identity':'old'};b={**a,'identity':'new'};s=g.Scan();s.rows={'x':b}
  events=g.reconcile(s,{'x':a},{'x':{'baseline':a,'purpose':'known'}})
  self.assertNotIn('已核实',events[0]['resolution'])
 def test_no_change_no_events(self):
  s=g.Scan();s.rows={'x':{'name':'ok','path':'/x'}};self.assertEqual(g.reconcile(s,s.rows,{}),[])
 def test_failure_never_deletes(self):
  e=g.reconcile(g.Scan(),{'x':{'name':'x','path':'/x'}},{})[0];self.assertIn('保留',e['resolution'])
 def test_invalid_name_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   for name in ['node','系统-项目-后台服务','系统/坏-项目-这是明确的用途说明']:
    with self.assertRaises(ValueError): g.validate_registration({'name':name,'purpose':'明确具体用途至少十二个字符的描述','project':d,'executable':'/bin/echo'})
 def test_report_escapes_untrusted_metadata(self):
  with tempfile.TemporaryDirectory() as d:
   g.report(pathlib.Path(d),{'at':'now','items':{'x':{'name':'<script>alert(1)</script>','kind':'app','path':'/x'}}},{})
   out=(pathlib.Path(d)/'项目用途看板.html').read_text();self.assertIn('&lt;script&gt;',out)
 def test_registration_exclusive_and_wrapper_works(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'Library/LaunchAgents').mkdir(parents=True);base=p/'base';base.mkdir()
   import shutil,subprocess,json
   shutil.copy2(pathlib.Path(__import__('os').environ.get('GUARDIAN_LAUNCHER',str(pathlib.Path(__file__).parent/'launcher'))),base/'launcher')
   manifest=p/'input.json';g.save(manifest,{'name':'系统维护-测试项目-输出安全测试完成标记','purpose':'仅用于验证规范入口的独立测试程序','project':str(p),'executable':'/usr/bin/true'})
   with mock.patch.object(g,'HOME',p):
    g.register(base,str(manifest),True)
    with self.assertRaises(ValueError):g.register(base,str(manifest),True)
   apps=list((base/'registered').glob('*/*.app'));exe=next((apps[0]/'Contents/MacOS').iterdir());self.assertEqual(subprocess.run([str(exe)]).returncode,0)
   (apps[0]/'Contents/Resources/original-executable').write_text(str(exe)+'\n');self.assertEqual(subprocess.run([str(exe)]).returncode,126)
 def test_argument_secrets_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(ValueError):g.validate_registration({'name':'系统维护-测试项目-输出安全测试完成标记','purpose':'仅用于验证规范入口的独立测试程序','project':d,'executable':'/bin/echo','arguments':['--token','fake']})
if __name__=='__main__':unittest.main()

class AutomaticScan(unittest.TestCase):
 def test_scan_executes_normalizer_before_collection(self):
  import os
  with tempfile.TemporaryDirectory() as d:
   calls=[];scan=g.Scan()
   with mock.patch.object(g,'run_automatic_naming',side_effect=lambda base:calls.append('normalize') or []),mock.patch.object(g.Scan,'run',side_effect=lambda:calls.append('collect') or scan):
    g.scan_once(pathlib.Path(d))
   self.assertEqual(calls,['normalize','collect'])
 def test_resolved_historical_item_is_not_a_current_action(self):
  scan=g.Scan();scan.rows={'启动服务:/x':{'kind':'启动服务','name':'local.x','path':'/x','executable':'/state/用途名称'}}
  self.assertEqual(g.current_actions(scan,[{'label':'local.x','name':'系统-项目-明确描述服务用途','status':'already_normalized'}]),[])
 def test_unknown_generic_service_is_current_action(self):
  scan=g.Scan();scan.rows={'launch':{'kind':'启动服务','name':'local.x','path':str(pathlib.Path.home()/'Library/LaunchAgents/local.x.plist'),'executable':'/usr/bin/python3'},'btm':{'kind':'后台注册','name':'python3','identifier':'8.local.x','path':'file:///x'}}
  self.assertEqual(g.current_actions(scan,[])[0]['label'],'local.x')
