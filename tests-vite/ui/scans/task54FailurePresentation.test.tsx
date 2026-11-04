import '@testing-library/jest-dom/vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import { ScanCheckFailure } from '@/features/scans/ScanCheckFailure';
import { ScanProgressPanel } from '@/features/scans/ScanProgressPanel';
import { ScanReportSections } from '@/pages/scans/ScanReportSections';
import { unavailableScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import { parseCurrentStatus, parseCurrentResults, parseCurrentSbom, parseCurrentVuln, type ScanTransport } from '@/shared/api/scans/scanTransport';
const id='00000000-0000-4000-8000-000000000054',digest=`sha256:${'a'.repeat(64)}`,image=`registry-1.docker.io/library/alpine@${digest}`,checkedAt='2026-11-02T00:00:00.000Z';
const detail={reason:'RESOURCE_LIMIT',stage:'inspection'};
const checks=['secret','sbom','vuln'] as const;
let client:QueryClient;
afterEach(()=>{cleanup();client?.clear();vi.restoreAllMocks();});
it.each(['PRIVATE_RAW_MARKER','SCAN_FAILED',undefined])('runtime failure fallback never echoes unknown source text: %s',reason=>{
  render(<ScanCheckFailure reason={reason} />);
  expect(screen.getByText(/Подробная причина не предоставлена/)).toBeVisible();expect(screen.getByText(/Проверьте доступные результаты остальных проверок/)).toBeVisible();expect(document.body.textContent).not.toContain('PRIVATE_RAW_MARKER');
});
it.each(checks)('runtime %s failure detail visible in progress/report; successful neighbors remain readable and reload stable',async failed=>{
  const secret={check:'secret',coverage:'image',outcome:'checked',errorCode:null,scannerVersion:'0.69.3',findingCount:0};
  const sbom={check:'sbom',coverage:'image',outcome:'checked',scannerVersion:'0.69.3',checkedAt,componentCount:1};
  const vuln={check:'vuln',coverage:'image',outcome:'checked',scannerVersion:'0.69.3',checkedAt,findingCount:0};
  const failures={secret:{...secret,outcome:'failed',errorCode:'SCAN_FAILED',findingCount:null,failureDetail:detail},sbom:{check:'sbom',coverage:'image',outcome:'failed',errorCode:'SCAN_FAILED',failureDetail:detail},vuln:{check:'vuln',coverage:'image',outcome:'failed',errorCode:'SCAN_FAILED',failureDetail:detail}};
  const wire={scanId:id,state:'partial',digest,imageReference:image,platform:'linux/amd64',checks,result:null,perCheck:{secret:failed==='secret'?failures.secret:secret,sbom:failed==='sbom'?failures.sbom:sbom,vuln:failed==='vuln'?failures.vuln:vuln}};
  const status=parseCurrentStatus(wire);
  const meta=(kind:typeof failed)=>({version:1,limit:25,offset:0,returnedCount:kind==='sbom'&&failed!=='sbom'?1:0,totalCount:kind===failed?null:kind==='sbom'?1:0,matchedCount:kind===failed?null:kind==='sbom'?1:0,sort:kind==='sbom'?'name:asc':kind==='vuln'?'severity:desc':'ruleId:asc',filters:kind==='sbom'?{ecosystem:null,name:null}:kind==='vuln'?{severity:null}:{ruleId:null,linePresence:null}});
  const transport:ScanTransport={...unavailableScanTransport,kind:'live',
    results:vi.fn(async()=>parseCurrentResults({findings:[],nextCursor:null,coverage:failed==='secret'?failures.secret:secret,page:meta('secret')},{view:'report-v1'})),
    sbom:vi.fn(async()=>parseCurrentSbom({...failed==='sbom'?{outcome:'failed',coverage:'image',errorCode:'SCAN_FAILED',components:[],failureDetail:detail}:{outcome:'checked',coverage:'image',image,platform:'linux/amd64',scannerVersion:'0.69.3',checkedAt,os:{name:'alpine',version:'3.21'},componentCount:1,components:[{ecosystem:'apk',name:'fixture-package',version:'1.0'}]},nextCursor:null,page:meta('sbom')},{view:'report-v1'})),
    vuln:vi.fn(async()=>parseCurrentVuln({...failed==='vuln'?{outcome:'failed',coverage:'image',errorCode:'SCAN_FAILED',failureDetail:detail}:{outcome:'checked',coverage:'image',image,platform:'linux/amd64',scannerVersion:'0.69.3',checkedAt,findingCount:0},findings:[],nextCursor:null,page:meta('vuln')},{view:'report-v1'})),
  };
  client=new QueryClient({defaultOptions:{queries:{retry:false}}});
  const tree=()=> <QueryClientProvider client={client}><MemoryRouter><ScanProgressPanel scan={status} /><ScanReportSections status={status} transport={transport} scope={['runtime-failure',failed]} demo={false} filter="all" onResetFilter={()=>{}} /></MemoryRouter></QueryClientProvider>;
  let view=render(tree());
  for(let reload=0;reload<2;reload++) {
    const inventory=screen.getByLabelText('Пакеты SBOM');fireEvent.click(within(inventory).getByText(/^Состав образа · найти пакет и его версию/,{selector:'summary'}));
    const region=failed==='sbom'?inventory:screen.getByRole('region',{name:failed==='secret'?'Возможные секреты':'Результаты Уязвимости'});
    expect(await within(region).findByText('Образ превысил ограничения проверки.')).toBeVisible();
    expect(within(region).getByText(/Для обработки образа потребовалось больше ресурсов/)).toBeVisible();
    expect(within(region).getByText(/Выберите меньшую сборку/)).toBeVisible();
    expect(within(screen.getByRole('group',{name:`Ход сканирования ${id}`})).getByText('Образ превысил ограничения проверки.')).toBeVisible();
    if(failed!=='sbom') expect(await screen.findByText('fixture-package')).toBeVisible();
    if(failed!=='secret') expect(await screen.findByText(/В выполненной проверке секретов находок нет/)).toBeVisible();
    if(failed!=='vuln') expect(await screen.findByText(/0 находок в выполненной проверенной области/)).toBeVisible();
    expect(document.body.textContent).not.toContain('100%');
    if(reload===0){view.unmount();view=render(tree());}
  }
  expect(transport.create).toBe(unavailableScanTransport.create);
});
