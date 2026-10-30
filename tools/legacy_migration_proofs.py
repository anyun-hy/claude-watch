#!/usr/bin/env python3
"""Reproduce migration issues using legacy code and temporary fixture homes only.

No actual profiles, services, network endpoints or application processes are used.
The JSON output is diagnostic evidence, never a launch authorization.
"""
from pathlib import Path
import json,sys,tempfile,copy,hashlib,importlib.util
from unittest.mock import patch
root=Path(__file__).resolve().parents[1];sys.path.insert(0,str(root/'monitor/Resources'))
from watch_switcher import session_guard as legacy
from watch_switcher import stun as legacy_stun
from watch_switcher import audit as legacy_audit
from watch_switcher.common import Paths,DEFAULT_CONFIG,save_config,atomic_json
from migration_reference import tag_reference
spec=importlib.util.spec_from_file_location('legacy_proof_roles',root/'monitor/Resources/process_roles.py')
roles=importlib.util.module_from_spec(spec);spec.loader.exec_module(roles)
class Fake:
 def __init__(self):self.now=1000.0
 def guard_egress(self,_):return {'ip':'1.1.1.1','country':'JP','observed_at':self.now,'source':'fixture'}
 def session_desktop_matches(self,_):return True
 def launcher_matches(self,_):return False
 def local(self,_):return {'context':'ctx','proxy':'ok','tun':'ok'}
def dns_probe(now,country='JP',*,status='complete',changed=False):
 return {'kind':'dns','status':status,'contextChanged':changed,'startedAt':now-2,'finishedAt':now,
         'errors':[] if status=='complete' else [{'stage':'dns','code':'timeout'}],
         'observations':[{'kind':'http','address':'1.1.1.1'},{'kind':'resolver','address':'8.8.8.8'}],
         'externalJSON':json.dumps([{'kind':'geoip','status':'complete','query':'1.1.1.1','data':{'country_code':'JP'}},
                                    {'kind':'geoip','status':'complete','query':'8.8.8.8','data':{'country_code':country}}])}
def audit(now):return {'ready':True,'observed_at':now,'expires_at':now+30,'context_id':'ctx','observation_id':'fixture','context_transition':{'state':'stable'},'egress_reference':{'ip':'1.1.1.1','country':'JP','checked_at':now,'context':'ctx','source':'fixture'}}
proofs={}
with tempfile.TemporaryDirectory(prefix='cw-legacy-proof-') as directory:
 home=Path(directory)/'home';home.mkdir();paths=Paths(home);save_config(paths,dict(DEFAULT_CONFIG));system=Fake()
 with patch('time.time',side_effect=lambda:system.now),patch('watch_switcher.automatic_policy.session_risk',side_effect=lambda *_:{'state':'safe','observed_at':system.now}):
  proofs['I01']={'multicast_accepted_by_old_egress':legacy._egress({'ip':'224.0.0.1','country':'JP','observed_at':1000}) is not None}
  value=legacy.begin_launch_session(paths,system,audit(1000));value=legacy.bind_launch_process(paths,value['session_id'],{'pid':77,'start_seconds':10,'start_microseconds':20})
  value['risk_evidence']['observed_at']='NaN';atomic_json(paths.base/'session-guard.json',value);system.now=2000.0
  out=legacy.check_session(paths,system,dict(DEFAULT_CONFIG),risk_reader=lambda *_:{'state':'unknown'})
  proofs['I02']={'elapsed_since_original_evidence':1000,'outcome':out['state'],'persisted_phase':legacy.read_session(paths)['state'],'invalid_time_bypassed_expiry':legacy.read_session(paths)['state']!='locked'}
  system.now=3000.0;old=legacy.begin_launch_session(paths,system,audit(system.now));system.now=3020.0
  original_lock=legacy.lock_session;new={}
  def interleave(*args,**kwargs):
   fresh=legacy.begin_launch_session(paths,system,audit(system.now));new['id']=fresh['session_id'];return original_lock(*args,**kwargs)
  with patch('watch_switcher.session_guard.lock_session',side_effect=interleave):out=legacy.check_session(paths,system,dict(DEFAULT_CONFIG))
  final=legacy.read_session(paths)
  proofs['I03']={'old_session':old['session_id'],'new_session':new['id'],'locked_session':final['session_id'],'locked_phase':final['state'],'old_pending_locked_new_session':final['session_id']==new['id'] and final['state']=='locked'}
 good=legacy_audit.record_dns_leak(paths,system,dns_probe(4000),now=4001)
 legacy_audit.record_dns_leak(paths,system,dns_probe(4003,status='timeout',changed=True),now=4004)
 status=legacy_audit.dns_receipt_status(paths,'ctx',now=4005)
 proofs['I07']={'context_changed_timeout_displays_old_pass':status['display_cached'],'still_blocks_launch':status['state']=='unknown'}
 modified=copy.deepcopy(good);modified['launch_expires_at']=5000
 state,_=legacy_audit._dns_receipt_state(modified,'ctx',launch=True,now=4100)
 proofs['I08']={'extended_persisted_expiry_accepted':state=='ok','actual_sample_age_seconds':100}
 bad=legacy_audit.record_dns_leak(paths,system,dns_probe(4010,'US'),now=4011)
 old=legacy_audit.record_dns_leak(paths,system,dns_probe(4005),now=4012)
 proofs['I09']={'newer_mismatch_state':bad['comparison']['state'],'late_old_state':old['comparison']['state'],
                'late_old_pass_replaced_newer_failure':legacy_audit.dns_receipt_status(paths,'ctx',launch=True,now=4013)['state']=='ok'}
 profile=home/'Library/Application Support/Claude';profile.mkdir(parents=True,exist_ok=True)
 (profile/'claude_desktop_config.json').write_text(json.dumps({'mcpServers':{'Server':{'command':'/usr/bin/python3','args':['-u','/tools/server.py','mcp']}}}))
 with patch.object(roles,'resolve',side_effect=lambda value:value):
  specs=roles.mcp_specs(home)
  hint=roles.classify(['/usr/bin/python3','-u','/tools/server.py','mcp'],'/usr/bin/python3',specs)
 proofs['I10']={'configured_interpreter_spec_loaded':bool(specs),'configured_interpreter_role_missing':not hint}
 runtime=home/'runtime.yaml';runtime.write_text('external-controller: 127.0.0.1:9090\nsecret: fixture-first\nsecret: fixture-second\n')
 controller,secret=tag_reference().controller_credentials(runtime)
 proofs['I11']={'duplicate_controller_secret_accepted':controller=='http://127.0.0.1:9090','later_secret_silently_ignored':secret=='fixture-first'}
assert proofs['I01']['multicast_accepted_by_old_egress']
assert proofs['I02']['invalid_time_bypassed_expiry']
assert proofs['I03']['old_pending_locked_new_session']
proofs['I06']={'empty_stun_probe_reported_complete':legacy_stun.probe(servers=(),budget=0)['complete']}
assert proofs['I06']['empty_stun_probe_reported_complete']
assert proofs['I07']['context_changed_timeout_displays_old_pass'] and proofs['I07']['still_blocks_launch']
assert proofs['I08']['extended_persisted_expiry_accepted']
assert proofs['I09']['late_old_pass_replaced_newer_failure']
assert proofs['I10']['configured_interpreter_spec_loaded'] and proofs['I10']['configured_interpreter_role_missing']
assert proofs['I11']['duplicate_controller_secret_accepted'] and proofs['I11']['later_secret_silently_ignored']
proofs['reference_sha256']=hashlib.sha256((root/'monitor/Resources/watch_switcher/session_guard.py').read_bytes()).hexdigest()
print(json.dumps(proofs,ensure_ascii=False,indent=2))
