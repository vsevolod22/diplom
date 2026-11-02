// Generic four-store evidence transfer. No live constructors or recovery authority.
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { recoverySqlite, validateExportManifest } from './public-image-stand.mjs';
import { sealedSnapshotDatabase, currentLlmFingerprint, currentHistorySchema, PUBLIC_LLM_EXPORT_PROGRAM } from './public-llm-stand.mjs';
import { readCurrentBackupExport, transferCurrentBackupSnapshot } from './public-current-backup-transfer.mjs';
import { writeExclusive, syncDirectory } from './setup-local-cve.mjs';

const need = ok => { if (!ok) throw Error('ADAPTER_SNAPSHOT_INVALID'); };
const same = (a,b) => JSON.stringify(a) === JSON.stringify(b);
// The current candidate's real constructors run twice on disposable copies only.
// The input environment is the validated public policy, never process.env or JWT.
export function qualifyAdapterStoreCopies({root,DB,directory,environment,baseline,verify}) {
  verify();const temp=fs.realpathSync(fs.mkdtempSync(join(tmpdir(),'deploy-adapter-stores-')));fs.chmodSync(temp,0o700);
  const copies=[['ledger','core/ledger.sqlite','ledger.sqlite',baseline.core.ledger.logicalSha256],
    ['history','llm/auth.sqlite','llm-history.sqlite',baseline.llm.history],['quota','llm/ledger.sqlite','llm-usage.sqlite',baseline.llm.quota]];
  try {
    for(const [,source,name]of copies){fs.copyFileSync(join(directory,source),join(temp,name),fs.constants.COPYFILE_EXCL);fs.chmodSync(join(temp,name),0o600);}
    const code=`import fs from 'node:fs';import {ScanLedger} from './src/ledger/ledger.ts';import {HistoryStore} from './src/llm/history-store.ts';import {QuotaLedger} from './src/llm/quota-ledger.ts';import {quotaPolicyFromEnvironment} from './src/llm/quota-policy.ts';try{const {directory,environment}=JSON.parse(fs.readFileSync(0,'utf8'));const policy=quotaPolicyFromEnvironment(environment);if(!policy)throw Error();const l=new ScanLedger(directory+'/ledger.sqlite');l.close();const h=new HistoryStore(directory+'/llm-history.sqlite',false);h.close();const q=new QuotaLedger(directory+'/llm-usage.sqlite',policy,Date.now,false);q.close();}catch{process.exitCode=70;}`;
    for(let pass=0;pass<2;pass++){
      verify();const r=spawnSync(process.execPath,['--import','tsx','--input-type=module','-e',code],{
        cwd:join(root,'server/api'),env:{PATH:'/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin'},input:JSON.stringify({directory:temp,environment}),encoding:'utf8',timeout:30000,maxBuffer:65536});
      need(r.status===0&&r.signal===null&&!r.error&&r.stdout==='');
      for(const [kind,,name,expected]of copies)need(currentLlmFingerprint(DB,fs,crypto,join(temp,name),kind)===expected);verify();
    }
    return {constructorPasses:2,ledgerUnchanged:true,historyUnchanged:true,quotaUnchanged:true};
  } finally {fs.rmSync(temp,{recursive:true,force:true});verify();}
}
export function createAdapterSnapshots({ DB, directory, helper, guard, record }) {
  const phases = ['fenced','before-api','after-api'];
  const seals = []; let next = 0;
  const seal = path => {
    const stamp = s => [s.dev,s.ino,s.mode,s.uid,s.nlink,s.size,s.mtimeMs,s.ctimeMs];
    const before = fs.lstatSync(path);
    need(before.isFile() && !before.isSymbolicLink() && before.nlink === 1 && before.uid === process.getuid() &&
      (before.mode & 0o7777) === 0o600 && before.size <= 256*1024**2);
    const hash = () => {
      need(same(stamp(before),stamp(fs.lstatSync(path))));
      const fd=fs.openSync(path,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW), h=crypto.createHash('sha256'), b=Buffer.alloc(65536);
      try { need(same(stamp(before),stamp(fs.fstatSync(fd)))); let n; while((n=fs.readSync(fd,b,0,b.length,null)))h.update(b.subarray(0,n)); }
      finally { fs.closeSync(fd); }
      need(same(stamp(before),stamp(fs.lstatSync(path))));
      for(const suffix of ['-wal','-shm','-journal'])need(!fs.existsSync(path+suffix));
      return h.digest('hex');
    };
    const expected=hash(); return () => need(hash()===expected);
  };
  const verify = () => { guard(); seals.forEach(check=>check()); };
  return Object.freeze({ verify, async capture(phase) {
    need(phase===phases[next]); verify();
    const dir=join(directory,phase); fs.mkdirSync(dir,{mode:0o700});syncDirectory(directory);
    await helper(phase,async (id, dispatch, check, receipt) => {
      need(receipt.ready===true && receipt.llmPresent===true);
      for(const group of ['core','llm']) {
        const destination=join(dir,group);fs.mkdirSync(destination,{mode:0o700});syncDirectory(dir);
        const read=request=>readCurrentBackupExport({request,check,phase,group,
          dispatch:r=>dispatch(['container','exec',id,'node','-e',PUBLIC_LLM_EXPORT_PROGRAM,JSON.stringify({group,request:r})])});
        const manifest=await read({action:'manifest'});validateExportManifest(manifest);
        writeExclusive(join(destination,'private-manifest.json'),JSON.stringify(manifest),0o600);syncDirectory(destination);
        for(const role of ['auth','ledger']) {
          await transferCurrentBackupSnapshot({dir:destination,role,manifest,readChunk:read,verify:check,phase,group});
          seals.push(seal(join(destination,role+'.sqlite')));
        }
        need(same(manifest,await read({action:'manifest'})));
      }
    });
    verify(); const SnapshotDB=sealedSnapshotDatabase(DB), paths={auth:join(dir,'core/auth.sqlite'),ledger:join(dir,'core/ledger.sqlite')};
    await recoverySqlite(SnapshotDB,fs,crypto,paths,null);
    // The exported fingerprint reader wraps DB itself; keep snapshot wrapping single-layer.
    const core=Object.fromEntries(Object.entries(paths).map(([name,path])=>[name,{logicalSha256:currentLlmFingerprint(DB,fs,crypto,path,name)}]));
    const history=join(dir,'llm/auth.sqlite'), quota=join(dir,'llm/ledger.sqlite');
    const llm={history:currentLlmFingerprint(DB,fs,crypto,history,'history'),quota:currentLlmFingerprint(DB,fs,crypto,quota,'quota')};
    const db=new SnapshotDB(history,{readonly:true,fileMustExist:true});let historyVersion;
    try { historyVersion=currentHistorySchema(db); } finally { db.close(); }
    need(historyVersion===4);verify();const result=Object.freeze({core,llm,historyVersion});
    record('snapshot-'+phase+'.json',result);next++;return result;
  }});
}
