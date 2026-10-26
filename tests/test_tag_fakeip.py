"""Destination equivalence for TUN: isolated OS, DNS and controller fixtures."""
import copy
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
from tests import test_tag_proxy as tag_tests
tag = tag_tests.tag


class FakeIPTests(unittest.TestCase):
    entry = tag_tests.TagTests.entry

    def setUp(self):
        tag_tests.TagTests.setUp(self)
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.config = Path(self.temp.name) / 'runtime.yaml'
        self.config.write_text('external-controller: 127.0.0.1:9090\nsecret: fixture\ndns:\n  enable: true\n  listen: :5353\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n')
        self.flow = {'pid':77,'protocol':'tcp','local':['198.18.0.1',50000],'peer':['198.18.1.10',443]}
        self.record['metadata'].update(sourceIP='198.18.0.1',type='Tun',dnsMode='fake-ip',destinationIP='',host='claude.ai')
        self.proof = {'kind':'same_core_fakeip_mapping','source_pid':77,'source_started':self.stamp,
                      'source':self.flow['local'],'peer':self.flow['peer'],'protocol':'tcp',
                      'connection_start':self.record['start'],'host':'claude.ai','address':'198.18.1.10',
                      'observed_at':self.now,'expires_at':self.now+1}
        self.kernel = subprocess.CompletedProcess([],0,'tcp46 0 0 *.5353 *.* LISTEN 0 0 1 1 mihomo:100\n','')
        self.processes = {100:self.owner,77:{'uid':os.getuid(),'stamp':self.stamp}}

    def correlate(self, record=None, proof=None, flow=None, records=None):
        with mock.patch.object(tag,'route_interface',return_value='utun4'):
            return tag.correlate_flow(flow or self.flow,self.stamp,self.api,records or [record or self.record],self.group,'JP11',self.now,
                                      {self.record['id']:self.proof if proof is None else proof})

    def collect(self, records=None, flows=None, current=None, processes=None, answer=None, kernel=None):
        records = [self.record] if records is None else records
        current = records if current is None else current
        with mock.patch.object(tag,'run_readonly',return_value=kernel or self.kernel), \
             mock.patch.object(tag,'route_interface',return_value='utun4'), \
             mock.patch.object(tag,'query_fakeip_dns',return_value=answer or ('198.18.1.10',1)) as query, \
             mock.patch.object(tag,'api_get',return_value={'connections':current}), \
             mock.patch.object(tag,'process_table',return_value=processes or self.processes):
            result = tag.collect_fakeip_evidence(str(self.config),self.entry(),self.api,records,
                       flows if flows is not None else [(self.flow,self.stamp,True)],self.processes)
            return result,query.call_count

    def test_valid_proof_preserves_actual_chain_and_missing_public_destination(self):
        r=self.correlate()
        self.assertEqual((r['association'],r['policy'],r['host']),('correlated','match','claude.ai'))
        self.assertEqual(r['destination_ip_state'],'missing');self.assertEqual(r['destination_ip'],'')
        self.assertEqual(r['association_evidence']['address'],'198.18.1.10')

    def test_absent_or_wrong_proof_never_correlates(self):
        variants=[None,{},dict(self.proof,host='other.example'),dict(self.proof,address='198.18.1.11'),
                  dict(self.proof,source_pid=78),dict(self.proof,source=['198.18.0.1',50001]),
                  dict(self.proof,source_started='different'),dict(self.proof,protocol='udp'),
                  dict(self.proof,connection_start='different'),dict(self.proof,expires_at=self.now-1),
                  dict(self.proof,observed_at=self.now+1),dict(self.proof,expires_at=self.now+30)]
        for value in variants:
            with self.subTest(value=value):
                self.assertEqual(self.correlate(proof=value or {})['association'],'unconfirmed')

    def test_original_source_protocol_identity_and_port_checks_still_hold(self):
        for key,value in [('sourceIP','198.18.0.2'),('sourcePort','50001'),('network','udp'),
                          ('processID',78),('destinationPort','444'),('type','HTTP'),('dnsMode','normal'),
                          ('host','unrelated.example'),('destinationIP','198.18.9.9'),('destinationIP','invalid')]:
            with self.subTest(key=key):
                r=copy.deepcopy(self.record);r['metadata'][key]=value
                self.assertEqual(self.correlate(record=r)['association'],'unconfirmed')
        r=copy.deepcopy(self.record);r['start']='2000-01-01T00:00:00Z'
        self.assertEqual(self.correlate(record=r)['association'],'unconfirmed')

    def test_resolved_public_destination_requires_exact_same_core_mapping(self):
        r=copy.deepcopy(self.record);r['metadata']['destinationIP']='160.79.104.10'
        self.assertEqual(self.correlate(record=r,proof={})['association'],'unconfirmed')
        result=self.correlate(record=r)
        self.assertEqual(result['association'],'correlated')
        self.assertEqual(result['destination_ip'],'160.79.104.10')
        for address in ('192.168.1.1','198.18.9.9','127.0.0.1','224.0.0.1'):
            r['metadata']['destinationIP']=address
            self.assertEqual(self.correlate(record=r)['association'],'unconfirmed')

    def test_shell_listener_snapshot_is_bounded_and_identity_checked(self):
        with mock.patch.object(tag,'run_readonly',side_effect=AssertionError('no repeated Python netstat')), \
             mock.patch.object(tag,'route_interface',return_value='utun4'), \
             mock.patch.object(tag,'query_fakeip_dns',return_value=('198.18.1.10',1)), \
             mock.patch.object(tag,'api_get',return_value={'connections':[self.record]}), \
             mock.patch.object(tag,'process_table',return_value=self.processes):
            args=(str(self.config),self.entry(),self.api,[self.record],[(self.flow,self.stamp,True)],self.processes)
            self.assertIn(self.record['id'],tag.collect_fakeip_evidence(*args,listener_snapshot=(self.kernel,self.now)))
            self.assertEqual(tag.collect_fakeip_evidence(*args,listener_snapshot=(self.kernel,self.now-6)),{})

    def test_duplicate_or_ambiguous_connection_id_never_passes(self):
        for id_value in (self.record['id'],'another-id'):
            r=copy.deepcopy(self.record);r['id']=id_value
            self.assertEqual(self.collect(records=[self.record,r])[0],{})
        self.assertEqual(self.correlate(records=[self.record,self.record])['association'],'unconfirmed')

    def test_proof_does_not_erase_policy_mismatch(self):
        r=copy.deepcopy(self.record);r['chains']=['JP-other',self.group]
        result=self.correlate(record=r)
        self.assertEqual((result['association'],result['policy']),('correlated','mismatch'))

    def test_collect_exact_same_core_destination(self):
        evidence,calls=self.collect()
        self.assertEqual(calls,1);self.assertIn(self.record['id'],evidence)
        self.assertEqual(evidence[self.record['id']]['dns_owner_pid'],100)

    def test_dns_mapping_difference_and_source_replacement_are_rejected(self):
        self.assertEqual(self.collect(answer=('198.18.1.11',1))[0],{})
        self.assertEqual(self.collect(answer=('8.8.8.8',1))[0],{})
        changed=copy.deepcopy(self.processes);changed[77]['stamp']='changed'
        self.assertEqual(self.collect(processes=changed)[0],{})
        changed=copy.deepcopy(self.processes);changed[100]['stamp']='changed'
        self.assertEqual(self.collect(processes=changed)[0],{})

    def test_different_dns_listener_owner_is_rejected_before_query(self):
        kernel=subprocess.CompletedProcess([],0,self.kernel.stdout.replace('mihomo:100','other:999'),'')
        self.assertEqual(self.collect(kernel=kernel),({},0))

    def test_closed_or_changed_controller_record_is_rejected(self):
        self.assertEqual(self.collect(current=[])[0],{})
        for field,value in [('host','other.example'),('destinationPort','444')]:
            changed=copy.deepcopy(self.record);changed['metadata'][field]=value
            self.assertEqual(self.collect(current=[changed])[0],{})
        self.assertEqual(self.collect(current=[self.record,self.record])[0],{})

    def test_udp_reused_source_port_never_guesses_destination(self):
        flow=dict(self.flow,protocol='udp');first=copy.deepcopy(self.record);first['metadata']['network']='udp'
        second=copy.deepcopy(first);second['id']='other';second['metadata']['host']='other.example'
        self.assertEqual(self.collect(records=[first,second],flows=[(flow,self.stamp,True)]),({},0))

    def test_runtime_range_bounds_and_invalid_process_sample(self):
        flow=dict(self.flow,peer=['198.19.1.10',443])
        self.assertEqual(self.collect(flows=[(flow,self.stamp,True)]),({},0))
        self.assertEqual(self.collect(flows=[(self.flow,self.stamp,False)]),({},0))

    def test_config_never_accepts_remote_dns_or_non_fake_range(self):
        original=self.config.read_text()
        for src,dst in [(':5353','8.8.8.8:53'),('198.18.0.1/16','0.0.0.0/0'),('fake-ip','redir-host')]:
            self.config.write_text(original.replace(src,dst))
            with self.assertRaises(ValueError):tag.fakeip_dns_config(str(self.config))
        self.config.write_text(original+'dns:\n  listen: :53\n')
        with self.assertRaises(ValueError):tag.fakeip_dns_config(str(self.config))

    def test_dns_parser_rejects_aliases_multiple_answers_errors_and_zero_ttl(self):
        good=';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 123\nclaude.ai. 1 IN A 198.18.1.10\n'
        with mock.patch.object(tag.subprocess,'run',return_value=subprocess.CompletedProcess([],0,good,'')) as runner:
            self.assertEqual(tag.query_fakeip_dns('claude.ai',5353,.2),('198.18.1.10',1))
            self.assertEqual(runner.call_args.args[0][:4],['/usr/bin/dig','@127.0.0.1','-p','5353'])
        for output in [good+good.splitlines()[-1]+'\n',good.replace('NOERROR','SERVFAIL'),good.replace(' 1 IN',' 0 IN'),
                       good.replace('claude.ai.','other.example.'),good.replace('IN A','IN CNAME'),'']:
            with mock.patch.object(tag.subprocess,'run',return_value=subprocess.CompletedProcess([],0,output,'')):
                with self.assertRaises(ValueError):tag.query_fakeip_dns('claude.ai',5353,.2)

    def test_invalid_host_never_queries_or_becomes_platform_evidence(self):
        for host in ['127.0.0.1','-bad.example','a..example','https://claude.ai','claude.ai\nother','a'*64+'.example']:
            self.assertIsNone(tag.normalized_dns_host(host))

    def test_queries_are_capped_and_share_a_single_deadline(self):
        records=[];flows=[]
        for i in range(10):
            r=copy.deepcopy(self.record);r['id']='id-'+str(i);r['metadata'].update(sourcePort=str(50000+i),host='h'+str(i)+'.example')
            f=copy.deepcopy(self.flow);f['local'][1]=50000+i
            records.append(r);flows.append((f,self.stamp,True))
        evidence,calls=self.collect(records=records,flows=flows)
        self.assertEqual(calls,8);self.assertEqual(len(evidence),8)
        with mock.patch.object(tag.time,'monotonic',side_effect=[0,0,2]):
            evidence,calls=self.collect(records=records,flows=flows)
            self.assertEqual(calls,1)

    def test_expired_mapping_after_controller_recheck_is_not_reused(self):
        elapsed=[0]
        def current(*args):
            elapsed[0]=3
            return {'connections':[self.record]}
        with mock.patch.object(tag,'run_readonly',return_value=self.kernel), \
             mock.patch.object(tag,'route_interface',return_value='utun4'), \
             mock.patch.object(tag,'query_fakeip_dns',return_value=('198.18.1.10',1)), \
             mock.patch.object(tag,'api_get',side_effect=current), \
             mock.patch.object(tag,'process_table',return_value=self.processes), \
             mock.patch.object(tag.time,'time',side_effect=lambda:self.now+elapsed[0]):
            result=tag.collect_fakeip_evidence(str(self.config),self.entry(),self.api,[self.record],[(self.flow,self.stamp,True)],self.processes)
            self.assertEqual(result,{})

    def test_no_fake_flows_does_not_add_system_or_dns_requests(self):
        self.assertEqual(self.collect(flows=[]),({},0))

if __name__=='__main__':unittest.main()
