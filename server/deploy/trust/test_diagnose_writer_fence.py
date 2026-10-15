#!/usr/bin/env python3
"""Focused INERT tests: synthetic metadata + pinned public definitions, never Docker."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import time
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('writer_fence_subject',HERE / 'diagnose_writer_fence.py')
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


def pinned_module(relative):
    raw = (d.REPO / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != d.PINS[relative]:
        raise AssertionError('Public definition source pin mismatch')
    return d.load_module(relative,raw)


with patch.object(subprocess,'Popen',side_effect=AssertionError('NO runtime')):
    c,t = pinned_module(d.CONTROLLER),pinned_module(d.TRANSPORT)

CANARY = 'SYNTHETIC_PRIVATE_NO_EXPORT'
ARGV = ['--diagnose-writer-fence-once','--source-sha256','a'*64,'--test-sha256','b'*64]


def fixture():
    volumes = [{'name':name,'driver':'local','scope':'local','options':{},
                'project':'dip-auth-stand','mountpoint':'/synthetic/'+CANARY+'/'+slot}
               for slot,name in c.VOLUMES.items()]
    ids = [c.RECONCILIATION_ORIGINALS[role][0] for role in ('egress','llm-egress')] + [d.INITIAL]
    rows = [{'id':identity,'running':identity != d.INITIAL,'mounts':[]} for identity in ids]
    retained = {'id':d.INITIAL,'image':d.OLD_IMAGE,'configImage':d.OLD_IMAGE,
        'name':'/dip-key-snapshot-'+'d'*32,'status':'created','running':False,'paused':False,
        'restarting':False,'oom':False,'dead':False,'exit':0,'restarts':0,
        'started':'0001-01-01T00:00:00Z','finished':'0001-01-01T00:00:00Z',
        'entry':['node'],'cmd':['-e',c.HOLDER_CODE],'args':['-e',c.HOLDER_CODE],'path':'node'}
    return volumes,ids,rows,retained


def encoded_rows(rows):
    return b'\n'.join(t.canonical(row) for row in rows) + (b'\n' if rows else b'')


def classify(volumes=None,ids=None,rows=None,retained=None,*,batch=None,before='public-daemon',after='public-daemon'):
    base = fixture()
    volumes,ids,rows,retained = [value if value is not None else original
        for value,original in zip((volumes,ids,rows,retained),base)]
    return d.classification(c,t,encoded_rows(volumes),before,after,ids,
                            encoded_rows(rows) if batch is None else batch,retained)


class InertTests(unittest.TestCase):
    def setUp(self):
        no_process = patch.object(subprocess,'Popen',side_effect=AssertionError('NO runtime'))
        no_process.start()
        self.addCleanup(no_process.stop)

    def private_receipt(self,result):
        raw = t.canonical(result)
        self.assertLessEqual(len(raw)+1,4096)
        for value in (CANARY,hashlib.sha256(CANARY.encode()).hexdigest(),'public-daemon',
                      '/synthetic/',str(d.REPO),d.OLD_IMAGE,'dip-key-snapshot-','dip-auth-stand'):
            self.assertNotIn(value.encode(),raw)
        self.assertEqual(result['notObserved'],list(d.NOT_OBSERVED))
        self.assertEqual(result['fullQualification'],'NOT_CLAIMED')
        self.assertFalse(result['mutation'])


class SourceTests(InertTests):
    def test_exact_frozen_pins_and_real_source_only_gate(self):
        for relative,pin in d.PINS.items():
            self.assertEqual(hashlib.sha256((d.REPO/relative).read_bytes()).hexdigest(),pin)
        argv = ARGV.copy()
        argv[2] = hashlib.sha256((d.REPO/d.SELF).read_bytes()).hexdigest()
        argv[4] = hashlib.sha256((d.REPO/d.TEST).read_bytes()).hexdigest()
        controller,transport,pins = d.source_gate(argv,time.monotonic()+10)
        self.assertEqual(tuple(controller.VOLUMES.values()),d.VOLUMES)
        self.assertEqual(transport.SOCKET,t.SOCKET)
        self.assertEqual(set(pins),set(d.PINS)|{d.SELF,d.TEST})
        # This is the real shared function from the source-bound controller, not a fixture oracle.
        self.assertTrue(controller.protected_store_touch({'Name':d.VOLUMES[0]},{}))

    def test_bad_source_pin_never_loads_or_launches(self):
        with patch.object(d,'public_bytes',return_value=b'wrong'),patch.object(d,'load_module') as load:
            result,status = d.run(ARGV)
        self.assertEqual((status,result['checkpoint']),(1,'PUBLIC_SOURCES'))
        self.assertEqual(result['category'],'PREDICATE_REFUSED')
        load.assert_not_called()
        self.private_receipt(result)

    def test_invalid_cli_has_no_reads(self):
        for argv in ([],ARGV+['--target','a'*64],['--once',*ARGV[1:]]):
            with patch.object(d,'source_gate') as gate:
                result,status = d.run(argv)
            self.assertEqual((status,result['checkpoint']),(1,'ARGUMENTS'))
            gate.assert_not_called()


class ClassificationTests(InertTests):
    def test_all_current_groups_independent_and_two_active_rows_not_qualification(self):
        result = classify()
        self.assertEqual(result['groups'],dict.fromkeys(d.GROUPS,True))
        self.assertEqual(result['shape'],[3,3,3,0,0,0,2])
        self.assertEqual(result['active'],sorted([
            [c.RECONCILIATION_ORIGINALS['egress'][0],2048],
            [c.RECONCILIATION_ORIGINALS['llm-egress'][0],4096]]))
        receipt = d.receipt(True,'COMPLETE','NONE',result)
        self.assertTrue(receipt['currentMatch'])
        self.private_receipt(receipt)

    def test_authoritative_names_exact_descendant_ancestor_root_and_nonoverlap(self):
        volumes,ids,rows,retained = fixture()
        source = volumes[0]['mountpoint']
        cases = [({'Type':'volume','Name':d.VOLUMES[0],'Source':'unrelated','RW':True},1|16|128),
                 ({'Type':'bind','Source':source,'RW':False},2|32|256),
                 ({'Type':'bind','Source':source+'/db.sqlite','RW':True},4|32|128),
                 ({'Type':'bind','Source':source.rsplit('/',1)[0],'RW':False},8|32|256),
                 ({'Type':'bind','Source':'/','RW':False},8|32|256),
                 ({'Type':'other','Source':source,'RW':False},2|64|256),
                 ({'Type':'bind','Source':source+'2','RW':True},0)]
        protected = {v['name']:{'Mountpoint':v['mountpoint']} for v in volumes}
        for mount,flags in cases:
            with self.subTest(case=flags):
                candidate = copy.deepcopy(rows)
                candidate[0]['mounts'] = [mount]
                result = classify(volumes,ids,candidate,retained)
                mask = dict(result['active'])[ids[0]]
                self.assertEqual(mask,2048|(flags|1024 if flags else 0))
                self.assertIs(result['groups']['NO_ACTIVE_TOUCH'],not bool(flags))
                self.assertIs(c.protected_store_touch(mount,protected),bool(flags))
                self.assertTrue(result['groups']['TOUCH_REASON_AGREEMENT'])
                self.private_receipt(d.receipt(True,'COMPLETE','NONE',result))

    def test_no_egress_or_foreign_ro_reader_exemption_and_stopped_mount_not_writer(self):
        volumes,ids,rows,retained = fixture()
        foreign = 'e'*64
        ids.append(foreign)
        rows.append({'id':foreign,'running':True,'mounts':[
            {'Type':'bind','Source':volumes[0]['mountpoint'],'RW':False}]})
        result = classify(volumes,ids,rows,retained)
        self.assertFalse(result['groups']['NO_ACTIVE_TOUCH'])
        self.assertEqual(dict(result['active'])[foreign],2|32|256|1024)
        rows[-1]['running'] = False
        result = classify(volumes,ids,rows,retained)
        self.assertTrue(result['groups']['NO_ACTIVE_TOUCH'])
        self.assertNotIn(foreign,dict(result['active']))

    def test_batch_count_duplicate_missing_unexpected_shape_and_decode_all_exposed(self):
        volumes,ids,rows,retained = fixture()
        cases = [(rows[:-1],b'',{'BATCH_COUNT','BATCH_COMPLETE'}),
                 ([rows[0],rows[0],rows[2]],b'',{'BATCH_UNIQUE','BATCH_COMPLETE'}),
                 ([rows[0],dict(rows[1],id='f'*64),rows[2]],b'',{'BATCH_IDS','BATCH_COMPLETE'}),
                 ([rows[0],dict(rows[1],running=1),rows[2]],b'',{'BATCH_SHAPE','BATCH_COMPLETE'}),
                 (None,b'{bad}\n'+encoded_rows(rows[1:]),{'BATCH_DECODE','BATCH_COMPLETE'})]
        for variant,raw,failed in cases:
            result = classify(volumes,ids,variant if variant is not None else rows,retained,
                              batch=raw or encoded_rows(variant))
            for group in failed:
                self.assertFalse(result['groups'][group])
            self.assertFalse(d.receipt(True,'COMPLETE','NONE',result)['currentMatch'])
        duplicate = classify(volumes,ids,[rows[0],rows[0],rows[2]],retained)
        self.assertEqual(duplicate['shape'][3:6],[1,1,0])
        missing = classify(volumes,ids,rows[:-1],retained)
        self.assertEqual(missing['shape'][4],1)

    def test_independent_groups_remain_visible_after_other_predicate_failures(self):
        volumes,ids,rows,retained = fixture()
        retained['status'] = 'running'
        retained['exit'] = True
        volumes[0]['driver'] = 'other'
        result = classify(volumes,ids,rows,retained,after='changed-daemon')
        for group in ('RETAINED_CREATED','RETAINED_COUNTERS','VOLUME_POLICY','DAEMON_EQUAL'):
            self.assertFalse(result['groups'][group])
        for group in ('RETAINED_FLAGS','BATCH_COMPLETE','CENSUS_UNIQUE','VOLUME_IDENTITY'):
            self.assertTrue(result['groups'][group])
        self.assertIsNone(result['groups']['NO_ACTIVE_TOUCH'])

    def test_malformed_mount_does_not_become_clear_or_hide_known_violation(self):
        volumes,ids,rows,retained = fixture()
        rows[0]['mounts'] = [None]
        rows[1]['mounts'] = [{'Type':'bind','Source':volumes[0]['mountpoint'],'RW':False}]
        result = classify(volumes,ids,rows,retained)
        self.assertFalse(result['groups']['MOUNT_SHAPE'])
        self.assertFalse(result['groups']['NO_ACTIVE_TOUCH'])
        self.assertTrue(dict(result['active'])[ids[0]] & 512)
        self.assertTrue(dict(result['active'])[ids[1]] & 1024)

    def test_batch_overflow_is_not_prefix_classified_and_malformed_mount_not_clear(self):
        volumes,ids,rows,retained = fixture()
        result = classify(volumes,ids,rows*11,retained)
        self.assertFalse(result['groups']['BATCH_COUNT'])
        self.assertFalse(result['groups']['BATCH_COMPLETE'])
        self.assertEqual(result['shape'][1:], [33,None,None,None,None,None])
        self.assertEqual(result['active'],[])
        self.assertIsNone(result['groups']['NO_ACTIVE_TOUCH'])
        rows[0]['mounts'] = [{'Type':'bind','Source':None,'RW':False}]
        result = classify(volumes,ids,rows,retained)
        self.assertFalse(result['groups']['MOUNT_SHAPE'])
        self.assertIsNone(result['groups']['NO_ACTIVE_TOUCH'])
        self.assertIsNone(result['groups']['TOUCH_REASON_AGREEMENT'])

    def test_32_active_rows_fit_closed_receipt_no_sampling(self):
        volumes,_,_,retained = fixture()
        ids = [format(index,'064x') for index in range(31)] + [d.INITIAL]
        rows = [{'id':identity,'running':True,'mounts':[
            {'Type':'bind','Source':volumes[0]['mountpoint'],'RW':False}]} for identity in ids]
        result = classify(volumes,ids,rows,retained)
        self.assertEqual(len(result['active']),32)
        self.assertFalse(result['groups']['INITIAL_BATCH_STOPPED'])
        self.private_receipt(d.receipt(True,'COMPLETE','NONE',result))


class PacketTests(InertTests):
    def execute(self,*,listing=None,batch_rows=None,fail=None):
        volumes,ids,rows,retained = fixture()
        calls = []
        def client(args,cap):
            calls.append((args,cap))
            if fail is not None and len(calls) == fail:
                raise t.Refused('CLIENT_TIMEOUT')
            if args == d.VOLUME_ARGS:
                return encoded_rows(volumes)
            if args == d.DAEMON_ARGS:
                return t.canonical('public-daemon')
            if args == d.CENSUS_ARGS:
                return listing if listing is not None else ('\n'.join(ids)+'\n').encode()
            if args == d.RETAINED_ARGS:
                return t.canonical(retained)
            self.assertEqual(args,('inspect','--type','container','--format',d.BATCH_FORMAT,*ids))
            return encoded_rows(rows if batch_rows is None else batch_rows)
        with patch.object(d,'source_gate',return_value=(c,t,{})),patch.object(t,'Client',return_value=client):
            result,status = d.run(ARGV)
        self.private_receipt(result)
        return result,status,calls

    def test_full_packet_exact_six_calls_no_actor_controller_or_private_method(self):
        with patch.object(c.Controller,'writers',side_effect=AssertionError('NO controller lifecycle')), \
                patch.object(c.Controller,'retained_created_unchanged',side_effect=AssertionError('NO private guards')):
            result,status,calls = self.execute()
        self.assertEqual((status,result['code']),(0,'CLASSIFIED'))
        self.assertTrue(result['currentMatch'])
        self.assertEqual(len(calls),6)
        self.assertEqual([call[0] for call in calls[:3]],[d.VOLUME_ARGS,d.DAEMON_ARGS,d.CENSUS_ARGS])
        self.assertEqual([call[0] for call in calls[4:]],[d.RETAINED_ARGS,d.DAEMON_ARGS])
        self.assertEqual([cap for _,cap in calls],[65536,4096,4096,2*1024**2,65536,4096])
        for args,_ in calls:
            self.assertNotIn('Env',' '.join(args))
            self.assertNotIn('Labels',' '.join(args).replace(d.VOLUME_FORMAT,''))

    def test_census_overflow_duplicate_bad_id_never_queries_subset(self):
        for ids in ([format(i,'064x') for i in range(33)],['a'*64,'a'*64],['--all']):
            result,status,calls = self.execute(listing=('\n'.join(ids)+'\n').encode())
            self.assertEqual(status,0)
            self.assertEqual(len(calls),5)
            self.assertFalse(result['currentMatch'])
            self.assertFalse(result['groups']['BATCH_COMPLETE'])
            self.assertEqual(result['shape'][1:], [None]*6)
            self.assertTrue(all(args[:5] != ('inspect','--type','container','--format',d.BATCH_FORMAT)
                                for args,_ in calls))

    def test_first_client_failure_is_sticky_no_retry_or_later_queries(self):
        for fail,stage in ((1,'VOLUMES'),(2,'DAEMON_BEFORE'),(3,'CENSUS'),(4,'BATCH'),
                           (5,'RETAINED'),(6,'DAEMON_AFTER')):
            result,status,calls = self.execute(fail=fail)
            self.assertEqual((status,result['checkpoint'],result['category']),(1,stage,'CLIENT_TIMEOUT'))
            self.assertEqual(len(calls),fail)

    def test_source_final_drift_refuses_without_more_clients(self):
        volumes,ids,rows,retained = fixture()
        outputs = [encoded_rows(volumes),t.canonical('public-daemon'),
                   ('\n'.join(ids)+'\n').encode(),encoded_rows(rows),
                   t.canonical(retained),t.canonical('public-daemon')]
        client = Mock(side_effect=outputs)
        pins = {d.SELF:hashlib.sha256(b'expected').hexdigest()}
        with patch.object(d,'source_gate',return_value=(c,t,pins)), \
                patch.object(t,'Client',return_value=client), \
                patch.object(d,'public_bytes',return_value=b'changed'):
            result,status = d.run(ARGV)
        self.assertEqual((status,result['checkpoint']),(1,'SOURCE_FINAL'))
        self.assertEqual(client.call_count,6)
        self.assertFalse(result['currentMatch'])
        self.private_receipt(result)

    def test_read_allowlist_rejects_every_mutation_and_repeat(self):
        fake = Mock(return_value=b'public')
        with patch.object(t,'Client',return_value=fake):
            client = d.ReadClient(t,time.monotonic()+60)
            for args in (('create','image'),('start',d.INITIAL),('rm',d.INITIAL),('exec',d.INITIAL,'true'),
                         ('inspect','--type','container','--format',d.BATCH_FORMAT,'a'*64)):
                with self.assertRaises(d.Refused):
                    client(args)
            fake.assert_not_called()
            client.set_batch([d.INITIAL])
            for args in (d.VOLUME_ARGS,d.DAEMON_ARGS,d.CENSUS_ARGS,client.batch,d.RETAINED_ARGS,d.DAEMON_ARGS):
                client(args)
            with self.assertRaises(d.Refused):
                client(d.DAEMON_ARGS)
            self.assertEqual(fake.call_count,6)


if __name__ == '__main__':
    unittest.main()
