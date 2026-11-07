import copy
import contextlib
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

try:
    import normalizer as n
except ModuleNotFoundError:
    n = None

class NormalizeSafety(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(n, 'automatic normalizer is not implemented')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        self.base = self.home/'state'
        self.agents = self.home/'Library/LaunchAgents'
        self.agents.mkdir(parents=True)
        self.base.mkdir()
        self.source = self.home/'worker.py'
        self.source.write_text('"""Local fixture worker with a concrete purpose."""\n')
        self.plist = self.agents/'local.test.worker.plist'
        self.original = {'Label':'local.test.worker','ProgramArguments':['/usr/bin/true',str(self.source),'--flag','test-value'], 'EnvironmentVariables':{'FIXTURE':'keep'},'KeepAlive':True,'RunAtLoad':True,'WorkingDirectory':str(self.home),'Disabled':True}
        self.plist.write_bytes(plistlib.dumps(self.original))
        launcher = Path(os.environ.get('GUARDIAN_LAUNCHER',str(Path(__file__).parent/'launcher')))
        shutil.copy2(launcher,self.base/'launcher')
        self.name = '系统维护-测试项目-校验启动项自动规范化功能'
    def rule(self):
        return n.enroll_rule(self.base,self.plist,self.name,[self.source],home=self.home)
    def normalize(self,**kw):
        return n.normalize(self.base,home=self.home,refresh=False,settle_seconds=0,**kw)
    def test_automatic_normalizer_exists(self):
        self.rule();result=self.normalize()
        self.assertEqual(result[0]['status'],'applied')
        d=plistlib.loads(self.plist.read_bytes())
        self.assertEqual(Path(d['Program']).name,self.name)
        comparable=copy.deepcopy(d);comparable.pop('Program');comparable.pop('AssociatedBundleIdentifiers');comparable['ProgramArguments'][0]='/usr/bin/true'
        self.assertEqual(comparable,self.original)
    def test_second_run_is_noop_and_original_target_never_overwritten(self):
        self.rule();self.normalize();before=self.plist.read_bytes()
        self.assertEqual(self.normalize()[0]['status'],'already_normalized')
        self.assertEqual(self.plist.read_bytes(),before)
        self.assertEqual(n.load_rules(self.base)[0]['target'],'/usr/bin/true')
    def test_explicit_version_rotation_preserves_settings_and_signed_rollback_wrapper(self):
        old=self.rule();self.normalize();old_entry=Path(old['wrapper'])
        newtarget=self.home/'new-release'/'bin'/'python';newtarget.parent.mkdir(parents=True)
        shutil.copyfile('/usr/bin/true',newtarget);newtarget.chmod(0o700)
        newsource=self.home/'new-release'/'main.py';newsource.write_text('"""New verified source."""\n')
        before=plistlib.loads(self.plist.read_bytes())
        result=n.rotate_rule(self.base,'local.test.worker',newtarget,[newsource],newtarget.parent.parent,
                             home=self.home,apply=True)
        self.assertEqual(result['status'],'rotated')
        rule=n.load_rules(self.base)[0];after=plistlib.loads(self.plist.read_bytes())
        self.assertEqual(rule['target'],str(newtarget))
        self.assertEqual(after['Program'],rule['wrapper'])
        self.assertEqual(after['ProgramArguments'][0],rule['wrapper'])
        self.assertEqual(after['WorkingDirectory'],str(newtarget.parent.parent))
        self.assertEqual(after['EnvironmentVariables'],before['EnvironmentVariables'])
        self.assertEqual(after['ProgramArguments'][1:],before['ProgramArguments'][1:])
        self.assertTrue(old_entry.is_file())
        subprocess.run(['codesign','--verify','--strict',str(old_entry.parent.parent.parent)],check=True)
        self.assertEqual(self.normalize()[0]['status'],'already_normalized')
        snapshot=self.plist.read_bytes()
        self.assertEqual(n.rotate_rule(self.base,'local.test.worker',newtarget,[newsource],newtarget.parent.parent,
                                       home=self.home,apply=True)['status'],'already_current')
        self.assertEqual(self.plist.read_bytes(),snapshot)
        n.rotate_rule(self.base,'local.test.worker',Path('/usr/bin/true'),[self.source],self.home,
                      home=self.home,apply=True)
        self.assertEqual(plistlib.loads(self.plist.read_bytes())['Program'],str(old_entry))
        self.assertEqual(self.normalize()[0]['status'],'already_normalized')
    def test_rotation_fails_closed_when_current_pinned_source_changed(self):
        self.rule();self.normalize();old_config=self.plist.read_bytes()
        self.source.write_text('"""Changed without approval."""\n')
        newtarget=self.home/'new-python';shutil.copyfile('/usr/bin/true',newtarget)
        with self.assertRaises(n.Protected):
            n.rotate_rule(self.base,'local.test.worker',newtarget,[self.source],self.home,
                          home=self.home,apply=True)
        self.assertEqual(self.plist.read_bytes(),old_config)
    def test_rotation_restores_rule_and_plist_if_rule_save_fails_after_commit(self):
        self.rule();self.normalize();before=self.plist.read_bytes();prior=n.load_rules(self.base)
        newcwd=self.home/'new-release';newcwd.mkdir()
        newtarget=newcwd/'python';shutil.copyfile('/usr/bin/true',newtarget)
        newsource=newcwd/'main.py';newsource.write_text('"""Safe new release."""\n')
        original_save=n.save;failed=False
        def save_then_fail(path,value):
            nonlocal failed
            original_save(path,value)
            if Path(path).name=='rules.json' and not failed:
                failed=True
                raise OSError('simulated post-commit persistence failure')
        with patch.object(n,'save',side_effect=save_then_fail):
            with self.assertRaises(OSError):
                n.rotate_rule(self.base,'local.test.worker',newtarget,[newsource],newcwd,
                              home=self.home,apply=True)
        self.assertEqual(self.plist.read_bytes(),before)
        self.assertEqual(n.load_rules(self.base),prior)
        self.assertEqual(self.normalize()[0]['status'],'already_normalized')
    def test_rotation_cli_requires_explicit_apply_and_preserves_existing_rule(self):
        import guardian as g
        self.rule();self.normalize();before=self.plist.read_bytes()
        work=self.home/'new-release';work.mkdir()
        exe=work/'python';shutil.copyfile('/usr/bin/true',exe)
        source=work/'main.py';source.write_text('"""Approved new release."""\n')
        argv=['guardian.py','--base',str(self.base),'rotate','local.test.worker',
              '--target',str(exe),'--source',str(source),'--working-directory',str(work)]
        with patch.object(g,'HOME',self.home),patch.object(sys,'argv',argv),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(n.Protected):g.main()
        self.assertEqual(self.plist.read_bytes(),before)
        out=io.StringIO()
        with patch.object(g,'HOME',self.home),patch.object(sys,'argv',argv+['--apply']),contextlib.redirect_stdout(out):
            g.main()
        self.assertEqual(json.loads(out.getvalue())['status'],'rotated')
        self.assertEqual(self.normalize()[0]['status'],'already_normalized')
    def test_update_reverting_name_is_automatically_restored(self):
        self.rule();self.normalize();self.plist.write_bytes(plistlib.dumps(self.original))
        self.assertEqual(self.normalize()[0]['status'],'applied')
        self.assertEqual(Path(plistlib.loads(self.plist.read_bytes())['Program']).name,self.name)
    def test_changed_source_is_not_implicitly_reapproved(self):
        self.rule();self.source.write_text('print("different behavior")')
        self.assertEqual(self.normalize()[0]['status'],'protected')
        self.assertEqual(plistlib.loads(self.plist.read_bytes()),self.original)
    def test_changed_arguments_are_protected(self):
        self.rule();d=copy.deepcopy(self.original);d['ProgramArguments'].append('--changed');self.plist.write_bytes(plistlib.dumps(d))
        self.assertEqual(self.normalize()[0]['status'],'protected')
    def test_reenrollment_cannot_replace_original_provenance(self):
        self.rule();self.normalize()
        with self.assertRaises(n.Protected):self.rule()
    def test_symlink_config_is_rejected(self):
        target=self.home/'other.plist';self.plist.rename(target);self.plist.symlink_to(target)
        with self.assertRaises(n.Protected):self.rule()
    def test_file_outside_user_agents_is_rejected(self):
        with self.assertRaises(n.Protected):n.enroll_rule(self.base,self.home/'outside.plist',self.name,[self.source],home=self.home)
    def test_missing_source_never_deletes_or_changes_config(self):
        self.rule();self.source.unlink();before=self.plist.read_bytes()
        self.assertEqual(self.normalize()[0]['status'],'protected');self.assertEqual(before,self.plist.read_bytes())
    def test_concurrent_atomic_replacement_is_not_overwritten(self):
        self.rule();changed=copy.deepcopy(self.original);changed['KeepAlive']=False
        def replace():
            p=self.plist.with_suffix('.new');p.write_bytes(plistlib.dumps(changed));os.replace(p,self.plist)
        self.assertEqual(self.normalize(before_commit=replace)[0]['status'],'protected')
        self.assertEqual(plistlib.loads(self.plist.read_bytes()),changed)
    def test_journal_has_no_arguments_or_environment_values(self):
        self.rule();self.normalize()
        text=''.join(p.read_text() for p in (self.base/'normalization/transactions').glob('*.json'))
        self.assertNotIn('test-value',text);self.assertNotIn('FIXTURE',text)
    def test_restore_preserves_later_unrelated_settings(self):
        self.rule();self.normalize();d=plistlib.loads(self.plist.read_bytes());d['EnvironmentVariables']['LATER']='keep';self.plist.write_bytes(plistlib.dumps(d))
        n.restore(self.base,'local.test.worker',home=self.home)
        d=plistlib.loads(self.plist.read_bytes());self.assertNotIn('Program',d);self.assertEqual(d['ProgramArguments'][0],'/usr/bin/true');self.assertEqual(d['EnvironmentVariables']['LATER'],'keep')
        self.assertFalse(n.load_rules(self.base)[0]['enabled'])
    def test_unloaded_service_is_never_bootstrapped(self):
        self.rule()
        with patch.object(n,'service_state',return_value={'loaded':False}),patch.object(n,'refresh_display',side_effect=AssertionError('must not start a service')):
            result=n.normalize(self.base,home=self.home,refresh=True,settle_seconds=0)
        self.assertEqual(result[0]['status'],'applied')
    def test_wrapper_self_reference_fails_closed(self):
        self.rule();self.normalize();d=plistlib.loads(self.plist.read_bytes());exe=Path(d['Program']);(exe.parent.parent/'Resources/original-executable').write_text(str(exe)+'\n')
        self.assertEqual(self.normalize()[0]['status'],'protected')
        self.assertEqual(subprocess.run([str(exe)]).returncode,126)
    def test_owned_request_is_automatically_enrolled_and_normalized(self):
        requests=self.base/'normalization/requests';requests.mkdir(parents=True)
        request=requests/'fixture.json';request.write_text(json.dumps({'plist':str(self.plist),'name':self.name,'purpose':'测试所有本机工具都可提交完整用途声明','sources':[str(self.source)]}));request.chmod(0o600)
        n.process_requests(self.base,home=self.home)
        self.assertEqual(self.normalize()[0]['status'],'applied')
    def test_config_metadata_is_preserved(self):
        self.rule();os.chmod(self.plist,0o640)
        # The mode itself is not behavioral identity and must survive atomic replacement.
        self.normalize();self.assertEqual(self.plist.stat().st_mode&0o777,0o640)
    def test_extended_attributes_are_preserved(self):
        self.rule()
        subprocess.run(['/usr/bin/xattr','-w','local.guardian.fixture','preserved',str(self.plist)],check=True)
        self.normalize()
        self.assertEqual(subprocess.check_output(['/usr/bin/xattr','-p','local.guardian.fixture',str(self.plist)]).strip(),b'preserved')
    def test_wrong_wrapper_identity_is_never_trusted(self):
        rule=self.rule();self.normalize();app=Path(rule['wrapper']).parent.parent.parent
        info=app/'Contents/Info.plist';d=plistlib.loads(info.read_bytes());d['CFBundleIdentifier']='different';info.write_bytes(plistlib.dumps(d))
        self.assertEqual(self.normalize()[0]['status'],'protected')
    def test_update_in_last_commit_window_is_never_overwritten(self):
        self.rule();changed=copy.deepcopy(self.original);changed['WorkingDirectory']='/different-updater-directory'
        real=n.exclusive_rename
        def concurrent(source,dest):
            if Path(dest)==self.plist and '.naming-' in Path(source).name:
                self.plist.write_bytes(plistlib.dumps(changed))
            return real(source,dest)
        with patch.object(n,'exclusive_rename',side_effect=concurrent):result=self.normalize()
        self.assertEqual(result[0]['status'],'protected');self.assertEqual(plistlib.loads(self.plist.read_bytes()),changed)
    def test_malformed_requests_do_not_block_valid_requests(self):
        inbox=self.base/'normalization/requests';inbox.mkdir(parents=True)
        for i,value in enumerate([[],{'plist':123},None]):
            p=inbox/(str(i)+'.json');p.write_text(json.dumps(value));p.chmod(0o600)
        p=inbox/'valid.json';p.write_text(json.dumps({'plist':str(self.plist),'name':self.name,'purpose':'完整的具体用途说明用于验证正常声明仍然处理','sources':[str(self.source)]}));p.chmod(0o600)
        n.process_requests(self.base,home=self.home)
        self.assertEqual(len(n.load_rules(self.base)),1)
        self.assertEqual(len(list((self.base/'normalization/request-results').glob('*.json'))),4)
    def test_restore_does_not_lose_concurrent_enrollment(self):
        import threading
        self.rule();self.normalize();other=self.agents/'local.test.other.plist';config=copy.deepcopy(self.original);config['Label']='local.test.other';other.write_bytes(plistlib.dumps(config))
        started=threading.Event();thread=[None]
        real=n.commit_config
        def concurrent(*args,**kwargs):
            def enroll():
                started.set();n.enroll_rule(self.base,other,'系统维护-其他项目-校验规则并发登记保护',[self.source],home=self.home)
            thread[0]=threading.Thread(target=enroll);thread[0].start();started.wait(1)
            # Old restore implementation does not hold rules.lock, so enrollment finishes here.
            thread[0].join(.1)
            return real(*args,**kwargs)
        with patch.object(n,'commit_config',side_effect=concurrent):n.restore(self.base,'local.test.worker',home=self.home)
        thread[0].join(2);self.assertFalse(thread[0].is_alive());self.assertEqual(len(n.load_rules(self.base)),2)
    def test_wrapper_is_registered_with_launchservices_for_system_display(self):
        self.rule();self.normalize()
        self.assertTrue(list((self.base/'normalization/launchservices').glob('*.json')))
    def test_interrupted_claim_is_recovered_without_overwriting_new_config(self):
        self.rule();raw=self.plist.read_bytes();recovery=self.agents/'.naming-recovery';recovery.mkdir(mode=0o700)
        claim=recovery/(self.plist.name+'.interrupted.original');self.plist.rename(claim)
        n.save(claim.with_suffix('.json'),{'path':str(self.plist),'claim':str(claim),'original_sha256':n.sha(raw),'expected_sha256':'pending'})
        self.assertEqual(self.normalize()[0]['status'],'applied')
        self.assertTrue(self.plist.exists());self.assertFalse(claim.exists())
    def test_config_write_has_fresh_mtime_for_backgroundtask_cache(self):
        self.rule();before=self.plist.stat().st_mtime_ns;self.normalize()
        self.assertGreater(self.plist.stat().st_mtime_ns,before)
    def test_process_death_after_claim_is_recovered_on_next_run(self):
        self.rule()
        code="""import os,sys
from pathlib import Path
import normalizer as n
real=n.exclusive_rename
def die(source,target):
 real(source,target)
 if str(target).endswith('.original'):os._exit(77)
n.exclusive_rename=die
n.normalize(Path(sys.argv[1]),home=Path(sys.argv[2]),refresh=False,settle_seconds=0)
"""
        result=subprocess.run(['/usr/bin/python3','-c',code,str(self.base),str(self.home)],cwd=str(Path(__file__).parent))
        self.assertEqual(result.returncode,77);self.assertFalse(self.plist.exists())
        self.assertEqual(self.normalize()[0]['status'],'applied');self.assertTrue(self.plist.exists());self.assertEqual(len(n.load_rules(self.base)),1)
    def test_interrupted_recovery_never_overwrites_updater(self):
        self.rule();raw=self.plist.read_bytes();recovery=self.agents/'.naming-recovery';recovery.mkdir(mode=0o700)
        claim=recovery/(self.plist.name+'.interrupted.original');self.plist.rename(claim)
        n.save(claim.with_suffix('.json'),{'path':str(self.plist),'claim':str(claim),'original_sha256':n.sha(raw),'expected_sha256':'pending'})
        changed=copy.deepcopy(self.original);changed['WorkingDirectory']='/new-updater';self.plist.write_bytes(plistlib.dumps(changed))
        self.assertEqual(self.normalize()[0]['status'],'protected');self.assertEqual(plistlib.loads(self.plist.read_bytes()),changed);self.assertTrue(claim.exists())
    def test_loaded_idle_service_can_refresh_without_enable_or_force(self):
        config=copy.deepcopy(self.original);config.pop('Disabled');self.plist.write_bytes(plistlib.dumps(config))
        self.rule();rule=n.load_rules(self.base)[0]
        result=type('Result',(),{'returncode':0})()
        with patch.object(n,'service_state',return_value={'loaded':True,'pid':None}),patch.object(n,'disabled_state',return_value='unspecified'),patch.object(n.subprocess,'run',return_value=result) as run:
            outcome=n.refresh_display(rule,{'loaded':True,'pid':None})
        self.assertTrue(outcome['attempted']);self.assertEqual(run.call_args.args[0],['/bin/launchctl','load',str(self.plist)])
    def test_disabled_services_never_refresh_or_enable(self):
        self.rule();rule=n.load_rules(self.base)[0]
        with patch.object(n.subprocess,'run',side_effect=AssertionError('must not invoke launchctl')):
            self.assertFalse(n.refresh_display(rule,{'loaded':True,'pid':None})['attempted'])
        d=copy.deepcopy(self.original);d.pop('Disabled');self.plist.write_bytes(plistlib.dumps(d))
        with patch.object(n,'disabled_state',return_value='true'),patch.object(n.subprocess,'run',side_effect=AssertionError('must not invoke launchctl')):
            self.assertFalse(n.refresh_display(rule,{'loaded':True,'pid':None})['attempted'])
    def test_runtime_changed_before_refresh_is_protected(self):
        d=copy.deepcopy(self.original);d.pop('Disabled');self.plist.write_bytes(plistlib.dumps(d));self.rule();rule=n.load_rules(self.base)[0]
        with patch.object(n,'disabled_state',return_value='unspecified'),patch.object(n,'service_state',return_value={'loaded':False}),patch.object(n.subprocess,'run',side_effect=AssertionError('must not invoke launchctl')):
            self.assertFalse(n.refresh_display(rule,{'loaded':True,'pid':7})['attempted'])
    def test_unknown_agent_stays_untouched(self):
        before=self.plist.read_bytes();self.assertEqual(self.normalize(),[]);self.assertEqual(before,self.plist.read_bytes())

if __name__=='__main__':unittest.main()
