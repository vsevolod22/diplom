"""Remote-only proposal. No local helper file/source change is authorized.
Default plan/self-test perform no process or private-file access. Execute is a
separate parent readonly authority for exactly one inspect and one logs call.
"""
import argparse
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

ROOT = Path('/Users/vsevolod/Documents/startup/diplom')
SCRATCH = ROOT.parent / 'cve14-proof-workspaces/run-20261010-history-wire-r2'
DOCKER = Path('/opt/homebrew/bin/docker')
TARGET = Path('/opt/homebrew/Cellar/docker/28.1.1/bin/docker')
LINK = '../Cellar/docker/28.1.1/bin/docker'
HOST = 'unix:///Users/vsevolod/.docker/run/docker.sock'
PROJECT = 'dip-history-wire-11eee17a73f3deae'
CID = 'f9e853aa61ce3a87ff4f51a4a5bdc998f2ba18e226ee39b5cfc094cf2a11eeaa'
IMAGE = 'sha256:c09ce4c8e6185784fad2c263b462952092fa89058d16363ebd543e0cd4bbd50d'
NAME = '/' + PROJECT + '-seed-1'
SEED = '/app/server/api/src/llm/tests/history-wire-native.seed.ts'
TEMPLATE = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
            '"project":{{json (index .Config.Labels "dip.history-wire.project")}},'
            '"run":{{json (index .Config.Labels "dip.history-wire.run")}},'
            '"user":{{json .Config.User}},"entrypoint":{{json .Config.Entrypoint}},'
            '"cmd":{{json .Config.Cmd}},"cwd":{{json .Config.WorkingDir}},'
            '"status":{{json .State.Status}},"exit":{{json .State.ExitCode}},"oom":{{json .State.OOMKilled}}}')
PATHS = {
    SEED: ('seed', 254),
    '/app/server/api/src/llm/tests/history-wire-native.api.ts': ('api_fixture', 107),
    '/app/server/api/src/llm/tests/history-wire-native.client.mjs': ('client_fixture', 349),
    '/app/server/api/src/llm/history-init.ts': ('history_init', 14),
    '/app/server/api/src/llm/history-runtime.ts': ('history_runtime', 17),
}
CLASSES = ('AssertionError', 'TypeError', 'RangeError', 'SyntaxError', 'SqliteError', 'Error')
CODES = ('ERR_ASSERTION', 'ERR_MODULE_NOT_FOUND', 'MODULE_NOT_FOUND', 'ERR_DLOPEN_FAILED',
         'ERR_UNKNOWN_FILE_EXTENSION', 'ERR_INVALID_ARG_TYPE', 'EPERM', 'EACCES', 'ENOENT')
REFUSAL = b'{"kind":"history-wire-seed-refusal","passed":false}'
CAP = 32768
SECONDS = 5

class Refused(Exception):
    pass

def need(condition, code):
    if not condition:
        raise Refused(code)

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()

def classify(raw):
    need(type(raw) is bytes and len(raw) <= CAP, 'capture_bound')
    lines = raw.splitlines()
    guarded = REFUSAL in lines
    classes, codes, frames = [], [], []
    for name in CLASSES:
        pattern = rb'(?m)^' + name.encode() + rb'(?: \[[A-Z_]{1,40}\])?:'
        if re.search(pattern, raw):
            classes.append(name)
    for code in CODES:
        pattern = rb'(?m)^[ \t]{0,8}code: [\x27\x22]' + code.encode() + rb'[\x27\x22],?[ \t]*$'
        header = rb'(?m)^(?:' + b'|'.join(c.encode() for c in CLASSES) + rb') \[' + code.encode() + rb'\]:'
        if re.search(pattern, raw) or re.search(header, raw):
            codes.append(code)
    found_frames = []
    for path, (label, maximum) in PATHS.items():
        pattern = (rb'(?m)^[ \t]{1,8}at (?:[^()\r\n]{1,160} \()?'
                   + rb'(?:file://)?' + re.escape(path.encode())
                   + rb':([1-9][0-9]{0,3}):[1-9][0-9]{0,3}\)?[ \t]*$')
        for match in re.finditer(pattern, raw):
            line = int(match.group(1))
            if line <= maximum and (label, line) not in found_frames:
                found_frames.append((label, line))
    frames = [{'source': label, 'line': line} for label, line in found_frames[:3]]
    signatures = bool(classes or codes or frames)
    category = ('mixed_guard_and_node_signature' if guarded and signatures else
                'guarded_seed_refusal_opaque' if guarded else
                'allowlisted_node_signature' if signatures else
                'empty_log' if not raw else 'no_allowlisted_signal')
    result = {'classification':category, 'seedRefusal':guarded, 'nodeClasses':classes,
              'nodeCodes':codes, 'frames':frames, 'frameLimitReached':len(found_frames)>3,
              'rawOutputIncluded':False, 'rootCauseEstablished':False, 'runtimeProofExecuted':False}
    need(len(encoded(result)) <= 1024, 'diagnostic_bound')
    return result

def parse_own(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'metadata_refused')
            result[key] = value
        return result
    try:
        v = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(Refused('metadata_refused')))
    except (ValueError, TypeError, UnicodeError):
        raise Refused('metadata_refused') from None
    expected = {'id':CID, 'name':NAME, 'image':IMAGE, 'project':PROJECT, 'run':PROJECT,
                'user':'65532:65532', 'entrypoint':['/usr/local/bin/node'],
                'cmd':['--import', 'tsx', 'src/llm/tests/history-wire-native.seed.ts', 'setup'],
                'cwd':'/app/server/api', 'status':'exited'}
    need(type(v) is dict and set(v) == set(expected) | {'exit','oom'}, 'metadata_refused')
    need(all(type(v[k]) is type(value) and v[k] == value for k, value in expected.items()), 'own_seed_refused')
    need(type(v['exit']) is int and 0 <= v['exit'] <= 255 and type(v['oom']) is bool, 'state_refused')
    return {'exitClass':'zero' if v['exit']==0 else 'one' if v['exit']==1 else 'other_nonzero', 'oomKilled':v['oom']}

def plain(path, directory=False):
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        need(not stat.S_ISLNK(current.lstat().st_mode), 'public_operand_refused')
    s = path.lstat()
    need(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode), 'public_operand_refused')
    return s

def qualify_public_tool_config():
    need(DOCKER.is_symlink() and os.readlink(DOCKER)==LINK, 'tool_refused')
    plain(DOCKER.parent, True)
    s = plain(TARGET)
    need(bool(s.st_mode & 0o111), 'tool_refused')
    plain(SCRATCH, True)
    plain(SCRATCH/'public-home', True)
    plain(SCRATCH/'public-docker-config', True)
    p = SCRATCH/'public-docker-config/config.json'
    s = plain(p)
    need(s.st_nlink==1 and s.st_size==3 and s.st_mode & 0o7777==0o600, 'public_config_refused')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        raw = os.read(fd, 4)
        after = os.fstat(fd)
        need(raw==b'{}\n' and all(getattr(before,k)==getattr(after,k)
             for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')), 'public_config_refused')
    finally:
        os.close(fd)

class Capture:
    def __init__(self):
        self.deadline = time.monotonic() + SECONDS
        self.bytes = 0
        self.calls = 0
        self.supervision_failed = False
    def run(self, args):
        allowed = (['container','inspect','--format',TEMPLATE,CID], ['container','logs','--tail','64',CID])
        need(args == allowed[self.calls] if self.calls < 2 else False, 'operation_refused')
        need(time.monotonic() < self.deadline, 'capture_deadline')
        self.calls += 1
        env = {'PATH':'/opt/homebrew/bin:/usr/bin:/bin', 'HOME':str(SCRATCH/'public-home'),
               'DOCKER_CONFIG':str(SCRATCH/'public-docker-config'), 'LANG':'C', 'LC_ALL':'C'}
        p = None
        selector = None
        raw = bytearray()
        try:
            p = subprocess.Popen([str(DOCKER),'--config',env['DOCKER_CONFIG'],'--host',HOST]+args,
                                 env=env, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, start_new_session=True)
            os.set_blocking(p.stdout.fileno(), False)
            selector = selectors.DefaultSelector()
            selector.register(p.stdout, selectors.EVENT_READ)
            while p.poll() is None or selector.get_map():
                left = self.deadline - time.monotonic()
                need(left > 0, 'capture_deadline')
                for key, _ in selector.select(min(.025, left)):
                    part = os.read(key.fileobj.fileno(), min(4096, CAP-self.bytes+1))
                    if not part:
                        selector.unregister(key.fileobj)
                    else:
                        self.bytes += len(part)
                        need(self.bytes <= CAP, 'capture_bound')
                        raw.extend(part)
            need(p.returncode==0, 'readonly_cli_failed')
            return bytes(raw)
        finally:
            if p is not None:
                try:
                    if p.poll() is None:
                        try: os.killpg(p.pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                        p.wait(timeout=.2)
                except (OSError, subprocess.SubprocessError):
                    self.supervision_failed = True
                finally:
                    if p.stdout is not None:
                        try: p.stdout.close()
                        except OSError: self.supervision_failed = True
            if selector is not None:
                try: selector.close()
                except OSError: self.supervision_failed = True

def self_test():
    canary = b'CANARY-private-never-publish'
    opaque = classify(REFUSAL + b'\n' + canary)
    need(opaque['classification']=='guarded_seed_refusal_opaque' and not opaque['frames'], 'self_test_refused')
    raw = (b'AssertionError [ERR_ASSERTION]: ' + canary + b'\n'
           + b'    at setup (' + SEED.encode() + b':157:42)\n'
           + b'  code: \x27ERR_ASSERTION\x27,\n')
    result = classify(raw)
    need(result['nodeClasses']==['AssertionError'] and result['nodeCodes']==['ERR_ASSERTION']
         and result['frames']==[{'source':'seed','line':157}] and canary not in encoded(result), 'self_test_refused')
    for path in ('/unknown'+SEED, '/host_mnt'+SEED, SEED+'/suffix', '/private/own.env', '/app/server/api/src/llm/tests/other.ts'):
        need(not classify(b'    at setup ('+path.encode()+b':157:42)\n')['frames'], 'self_test_refused')
    need(not classify(b'    at setup ('+SEED.encode()+b':9999:42)\n')['frames'], 'self_test_refused')
    need(classify(canary)['classification']=='no_allowlisted_signal', 'self_test_refused')
    expected = {'id':CID, 'name':NAME, 'image':IMAGE, 'project':PROJECT, 'run':PROJECT,
                'user':'65532:65532', 'entrypoint':['/usr/local/bin/node'],
                'cmd':['--import','tsx','src/llm/tests/history-wire-native.seed.ts','setup'],
                'cwd':'/app/server/api', 'status':'exited', 'exit':1, 'oom':False}
    need(parse_own(encoded(expected))=={'exitClass':'one','oomKilled':False}, 'self_test_refused')
    for key in ('id','name','image','project','run','user','cmd','status'):
        try: parse_own(encoded({**expected, key:'CANARY-private'}))
        except Refused: pass
        else: raise Refused('self_test_refused')
    try: classify(b'x'*(CAP+1))
    except Refused: pass
    else: raise Refused('self_test_refused')
    need(len(encoded(classify(raw)))<=1024, 'self_test_refused')
    return {'selfTestPassed':True, 'engineCalls':0, 'sourceWrites':0, 'rawOutputIncluded':False}

def plan():
    return {'kind':'history-r2-own-seed-log-diagnostic-proposal', 'executed':False,
            'executionApproved':False, 'containerId':CID, 'project':PROJECT, 'image':IMAGE,
            'fixtureFreezeSha256':'11eee17a73f3deae70512740f732cdce44a746053454ef1ac8cf17f36cfb6a67',
            'readonlyCalls':['one-fixed-container-inspect','one-fixed-container-logs-tail-64'],
            'captureDeadlineSeconds':SECONDS, 'aggregateCaptureBytes':CAP, 'diagnosticBytes':1024,
            'privateFilesRead':False, 'publicOwnEmptyConfigReadOnly':True, 'rawLogsPublished':False,
            'noRetry':True, 'seedCatchMayBeOpaque':True, 'newRepositoryFileAuthorized':False}

def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--self-test', action='store_true')
    mode.add_argument('--execute', action='store_true')
    parser.add_argument('--parent-readonly-diagnostic-authorized', action='store_true')
    args = parser.parse_args()
    capture = None
    stage = 'authority'
    try:
        if args.self_test: return self_test()
        if not args.execute: return plan()
        need(args.parent_readonly_diagnostic_authorized, 'new_parent_authority_required')
        stage = 'public-tool-config'
        qualify_public_tool_config()
        capture = Capture()
        stage = 'own-seed-inspect'
        metadata = capture.run(['container','inspect','--format',TEMPLATE,CID])
        need(not capture.supervision_failed, 'local_supervision_refused')
        state = parse_own(metadata)
        stage = 'own-seed-logs'
        result = classify(capture.run(['container','logs','--tail','64',CID]))
        need(not capture.supervision_failed, 'local_supervision_refused')
        result.update(state, ownSeedQualified=True, captureBytes=capture.bytes, readonlyCalls=capture.calls)
        need(len(encoded(result))<=1024, 'diagnostic_bound')
        return result
    except Refused as error:
        return {'classification':str(error), 'stage':stage, 'rawOutputIncluded':False,
                'localSupervisionFailed':bool(capture and capture.supervision_failed),
                'runtimeProofExecuted':False, 'rootCauseEstablished':False}
    except KeyboardInterrupt:
        return {'classification':'parent_interrupt_stopped', 'stage':stage, 'rawOutputIncluded':False,
                'runtimeProofExecuted':False, 'rootCauseEstablished':False}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, subprocess.SubprocessError):
        return {'classification':'tool_or_io_refused', 'stage':stage, 'rawOutputIncluded':False,
                'localSupervisionFailed':bool(capture and capture.supervision_failed),
                'runtimeProofExecuted':False, 'rootCauseEstablished':False}

if __name__ == '__main__':
    result = main()
    out = encoded(result)
    if len(out) > 4096:
        out = b'{"classification":"diagnostic_bound","rawOutputIncluded":false}'
    sys.stdout.buffer.write(out+b'\n')
