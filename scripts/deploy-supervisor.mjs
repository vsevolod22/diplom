// Import-safe, prospective-only OS lease. Never deletes or reclaims a lock file.
import * as fs from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { STATE } from './public-image-stand.mjs';
import { deploymentFailure } from './deploy-core.mjs';

const PYTHON = '/usr/bin/python3';
const NAME = '.deploy-supervisor-v1.lock';
const FD_ENV = 'DIP_DEPLOY_SUPERVISOR_FD';
const SESSION_ENV = 'DIP_DEPLOY_SUPERVISOR_SESSION';
export const DEPLOY_SUPERVISOR_PROGRAM = String.raw`
import os, sys, stat, fcntl, subprocess, secrets, json
child_started = False
mode = None
def failure(busy=False):
    # Only pre-child failures are ours to report; the child owns its own JSON.
    print(json.dumps(dict(ok=False, mode=mode, phase='supervisor',
        code='DEPLOY_LOCKED' if busy else 'DEPLOY_ADAPTER',
        message='Deployment supervisor lease is busy.' if busy else 'Deployment supervisor unavailable.',
        retryable=busy, state='unchanged', lock='not-acquired', rollback='not-needed',
        keptOldServing=None, needsRecovery=False,
        nextAction='Preserve all locks and evidence; verify supervisor ownership before retrying.')), flush=True)
try:
    root, state, node, entry, action, *args = sys.argv[1:]
    mode = args[0] if args and args[0] in ('app', 'recover') else None
    assert os.path.realpath(root) == root and os.path.realpath(state) == state
    d = os.lstat(state)
    assert stat.S_ISDIR(d.st_mode) and d.st_uid == os.getuid() and stat.S_IMODE(d.st_mode) == 0o700
    path = os.path.join(state, '.deploy-supervisor-v1.lock')
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    if action == 'new':
        try:
            fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            os.fsync(fd)
            directory = os.open(state, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
        except FileExistsError:
            fd = os.open(path, flags)
    else:
        assert action == 'recover'
        fd = os.open(path, flags)
    s = os.fstat(fd)
    assert stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600 and s.st_size == 0
    assert (s.st_dev, s.st_ino) == (os.lstat(path).st_dev, os.lstat(path).st_ino)
    try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        failure(True)
        sys.exit(2)
    env = dict(os.environ)
    env['DIP_DEPLOY_SUPERVISOR_FD'] = str(fd)
    env['DIP_DEPLOY_SUPERVISOR_SESSION'] = secrets.token_hex(32)
    child = subprocess.Popen([node, entry, *args], cwd=root, env=env, pass_fds=(fd,))
    child_started = True
    # Both processes own the same open description. Parent death cannot release
    # the lease while the coordinator still lives. Never unlock explicitly.
    status = child.wait()
    sys.exit(status if 0 <= status <= 255 else 1)
except SystemExit:
    raise
except BaseException:
    if not child_started: failure()
    sys.exit(1)
`;
const PROBE = String.raw`
import os, sys, stat, fcntl
try:
    path, mode = sys.argv[1:]
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    s = os.fstat(fd)
    assert stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600 and s.st_size == 0
    if mode == 'free':
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    else:
        inherited = os.fstat(3)
        assert (s.st_dev, s.st_ino) == (inherited.st_dev, inherited.st_ino)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            sys.exit(1)  # No existing lease: an inherited but unlocked fd is insufficient.
        except BlockingIOError:
            pass
        # This succeeds only for the SAME locked open-file description.
        fcntl.flock(3, fcntl.LOCK_EX | fcntl.LOCK_NB)
    sys.exit(0)
except Exception:
    sys.exit(1)
`;
const refuse = () => { throw Error('DEPLOY_SUPERVISOR_REQUIRED'); };
function pathFor(root) {
  if (resolve(root) !== root || fs.realpathSync(root) !== root) refuse();
  const dir = join(root, STATE), s = fs.lstatSync(dir);
  if (!s.isDirectory() || s.isSymbolicLink() || s.uid !== process.getuid() || (s.mode & 0o7777) !== 0o700) refuse();
  return join(dir, NAME);
}
function identity(path, fd) {
  const a = fs.lstatSync(path), b = fd === undefined ? a : fs.fstatSync(fd);
  if (!a.isFile() || a.isSymbolicLink() || a.uid !== process.getuid() || a.nlink !== 1 || a.size !== 0 ||
    (a.mode & 0o7777) !== 0o600 || a.dev !== b.dev || a.ino !== b.ino) refuse();
  return { dev: a.dev, ino: a.ino };
}
export function hasDeploySupervisor() { return Object.hasOwn(process.env, FD_ENV); }
export function requireDeploySupervisor(root) {
  const path = pathFor(root), text = process.env[FD_ENV], session = process.env[SESSION_ENV];
  if (!/^[0-9]+$/.test(text ?? '') || !/^[a-f0-9]{64}$/.test(session ?? '')) refuse();
  const fd = Number(text); if (!Number.isSafeInteger(fd) || fd < 3) refuse();
  const original = identity(path, fd);
  const r = spawnSync(PYTHON, ['-I', '-c', PROBE, path, 'owned'], { stdio: ['ignore', 'ignore', 'ignore', fd], timeout: 5000 });
  if (r.error || r.signal || r.status !== 0) refuse();
  const verify = () => {
    if (pathFor(root) !== path) refuse();
    const current = identity(path, fd);
    if (current.dev !== original.dev || current.ino !== original.ino) refuse();
  };
  verify();
  return Object.freeze({ version: 1, session, identity: Object.freeze(original), verify });
}
export function inspectDeploySupervisor(root) {
  const path = pathFor(root), original = identity(path);
  const r = spawnSync(PYTHON, ['-I', '-c', PROBE, path, 'free'], { stdio: 'ignore', timeout: 5000 });
  if (r.error || r.signal || r.status !== 0) refuse();
  const current = identity(path);
  if (pathFor(root) !== path || current.dev !== original.dev || current.ino !== original.ino) refuse();
  return Object.freeze(original); // Momentary read-only observation, NEVER an apply authorization.
}
export async function superviseDeployment(root, argv) {
  const state = join(root, STATE); pathFor(root);
  const entry = fileURLToPath(new URL('./deploy.mjs', import.meta.url));
  if (!Array.isArray(argv) || !['app', 'recover'].includes(argv[0])) refuse();
  const env = { ...process.env }; delete env[FD_ENV]; delete env[SESSION_ENV];
  return new Promise(resolveResult => {
    const child = spawn(PYTHON, ['-I', '-c', DEPLOY_SUPERVISOR_PROGRAM, root, state, process.execPath, entry,
      argv[0] === 'recover' ? 'recover' : 'new', ...argv], { cwd: root, env, stdio: 'inherit' });
    child.once('error', () => {
      console.log(JSON.stringify(deploymentFailure(null, { mode: argv[0], phase: 'supervisor', fallback: 'DEPLOY_ADAPTER' })));
      resolveResult(1);
    });
    child.once('exit', (code, signal) => resolveResult(!signal && Number.isInteger(code) ? code : 1));
  });
}
