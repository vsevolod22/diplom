import '@testing-library/jest-dom/vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanDetailPage } from '@/pages/scans/ScanDetailPage';
import { LiveScanContext, type LiveContext } from '@/features/scans/liveScanContext';
import { fixtureScanTransport, unavailableScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import { ScanAccessError, ScanHttpError } from '@/shared/api/scans/httpScanTransport';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import type { ScanStatus, ScanTransport } from '@/shared/api/scans/scanTransport';

// Ten cases only. Reviewer follow-up cases await source freeze before execution.
const id = '00000000-0000-4000-8000-000000000057';
const digest = `sha256:${'a'.repeat(64)}`;
const image = `registry-1.docker.io/library/alpine@${digest}`;
const scope: LiveContext['scope'] = ['live-scans', 54, 'stale-owner'];
const clients: QueryClient[] = [];
const completed: ScanStatus = { scanId:id, state:'completed', digest, imageReference:image, platform:'linux/amd64', checks:['secret'],
  perCheck:{secret:{check:'secret',coverage:'image',outcome:'checked',findingCount:1,scannerVersion:'0.69.3'}} };
function transportFor(status: ScanStatus): ScanTransport {
  return { ...unavailableScanTransport, kind:'live', capabilities:{list:true,create:false,cancel:true,events:false},
    get:vi.fn(async()=>status),
    results:vi.fn<ScanTransport['results']>(async()=>({findings:[{findingId:'verified-secret',category:'secret',ruleId:'VERIFIED_RULE',severity:'unknown',line:7}],nextCursor:null,
      coverage:[{check:'Secrets',status:'checked',findingCount:1,scannerVersion:'0.69.3'}],
      page:{version:1,limit:25,offset:0,returnedCount:1,totalCount:1,matchedCount:1,sort:'ruleId:asc',filters:{ruleId:null,linePresence:null}}})),
    cancel:vi.fn(async()=>{}),create:vi.fn(async()=>{throw Error('No launch allowed');}),
  };
}
function mount(transport:ScanTransport,gcTime=0) {
  const client=new QueryClient({defaultOptions:{queries:{retry:false,gcTime}}});clients.push(client);
  transitionScanSession(scope[2],client,true);
  const content=(currentScope:LiveContext['scope']=scope)=><QueryClientProvider client={client}><LiveScanContext.Provider value={{scope:currentScope,transport}}>
    <MemoryRouter initialEntries={[`/scans/${id}`]}><Routes><Route path="/scans/:scanId" element={<ScanDetailPage />} /></Routes></MemoryRouter>
  </LiveScanContext.Provider></QueryClientProvider>;
  return {client,content,...render(content())};
}
function expectNoPrivateData() {
  expect(screen.queryByText('Строка 7')).toBeNull();
  expect(screen.queryByRole('group',{name:`Ход сканирования ${id}`})).toBeNull();
  expect(document.querySelector('.scan-report-overview')).toBeNull();
}
function expectNoStaleMutationActions() {
  const names=/Отменить скан|Подтвердить отмену|Сформировать|Включить.*разбор|Отправить вопрос|Сохранить решение|Перевести/;
  for(const button of screen.queryAllByRole('button',{name:names})) expect(button).toBeDisabled();
}
beforeEach(()=>{
  vi.stubGlobal('IntersectionObserver',class{observe(){}unobserve(){}disconnect(){}});
  // AI metadata is unavailable; no live request or provider/mutation is permitted.
  vi.stubGlobal('fetch',vi.fn(async(_input:RequestInfo|URL,init?:RequestInit)=>{
    if(init?.method==='POST') throw Error('Forbidden mutation in stale snapshot regression');
    return new Response(JSON.stringify({errorCode:'LLM_UNAVAILABLE'}),{status:503,headers:{'content-type':'application/json'}});
  }));
});
afterEach(()=>{cleanup();for(const client of clients.splice(0))client.clear();transitionScanSession(null,new QueryClient(),true);vi.restoreAllMocks();vi.unstubAllGlobals();});

it('background503 retains verified completed snapshot/findings with visible stale warning, without stale mutations',async()=>{
  const transport=transportFor(completed);const view=mount(transport);
  expect(await screen.findByText('Строка 7')).toBeVisible();
  vi.mocked(transport.get).mockRejectedValueOnce(new ScanHttpError(503,'SCANNER_UNAVAILABLE'));
  await act(async()=>{await view.client.invalidateQueries({queryKey:[...scope,'scan',id]});});
  await waitFor(()=>expect(view.client.getQueryState([...scope,'scan',id])?.status).toBe('error'));
  expect(screen.getByText('Строка 7')).toBeVisible();expect(document.querySelector('.scan-report-overview')).not.toBeNull();
  expect(screen.getAllByRole('alert').some(alert=>/последн|устар|не удалось обнов|актуальност/i.test(alert.textContent??''))).toBe(true);
  expect(view.client.getQueryData([...scope,'scan',id])).toEqual(completed);expectNoStaleMutationActions();expect(transport.cancel).not.toHaveBeenCalled();expect(transport.create).not.toHaveBeenCalled();
});
it('background network failure retains active verified progress but cannot authorize stale cancel',async()=>{
  const running:ScanStatus={...completed,state:'running',percent:23,perCheck:{secret:null}};
  const transport=transportFor(running);const view=mount(transport);
  await screen.findByRole('progressbar');expect(screen.getByRole('button',{name:'Отменить скан'})).toBeEnabled();
  vi.mocked(transport.get).mockRejectedValueOnce(new TypeError('Failed to fetch'));
  await act(async()=>{await view.client.invalidateQueries({queryKey:[...scope,'scan',id]});});
  await waitFor(()=>expect(view.client.getQueryState([...scope,'scan',id])?.status).toBe('error'));
  expect(screen.getByRole('group',{name:`Ход сканирования ${id}`})).toBeVisible();expect(screen.getByRole('progressbar')).toHaveAttribute('value','23');
  expect(screen.getAllByRole('alert').some(alert=>/последн|устар|не удалось обнов|актуальност/i.test(alert.textContent??''))).toBe(true);
  expectNoStaleMutationActions();expect(transport.cancel).not.toHaveBeenCalled();
});
it('fatal coded503 AUTH_UNAVAILABLE or unknown hides verified snapshot instead of stale fallback',async()=>{
  for(const code of ['AUTH_UNAVAILABLE','UNEXPECTED_BACKEND_FAILURE']) {
  const transport=transportFor(completed);const view=mount(transport);
  await screen.findByText('Строка 7');
  expect(view.client.getQueryState([...scope,'scan',id])?.status).toBe('success');
  vi.mocked(transport.get).mockRejectedValueOnce(new ScanHttpError(503,code));
  await act(async()=>{await view.client.invalidateQueries({queryKey:[...scope,'scan',id]});});
  await waitFor(()=>expect(view.client.getQueryState([...scope,'scan',id])?.status).toBe('error'));
  expectNoPrivateData();expectNoStaleMutationActions();
  expect(document.querySelector('.scan-a1__reference')).not.toHaveTextContent('registry-1.docker.io/library/alpine');
  expect(view.client.getQueryData([...scope,'scan',id])).toEqual(completed);
  expect(screen.getAllByRole('alert').some(alert=>/последний подтверждённый снимок/.test(alert.textContent??''))).toBe(false);
  // Each code starts from independently verified data; a prior fatal latch cannot mask misclassification.
  // A later transient failure must not re-authorize data retired by either fatal response.
  vi.mocked(transport.get).mockRejectedValueOnce(new TypeError('Failed to fetch'));
  await act(async()=>{await view.client.invalidateQueries({queryKey:[...scope,'scan',id]});});
  expect(transport.get).toHaveBeenCalledTimes(3);
  expect(view.client.getQueryState([...scope,'scan',id])?.status).toBe('error');
  expect(view.client.getQueryData([...scope,'scan',id])).toEqual(completed);
  expectNoPrivateData();expectNoStaleMutationActions();
  expect(document.querySelector('.scan-a1__reference')).not.toHaveTextContent('registry-1.docker.io/library/alpine');
  expect(transport.cancel).not.toHaveBeenCalled();expect(transport.create).not.toHaveBeenCalled();
  view.unmount();
  }
});
it('same-session cache remount retains verified snapshot on first background503/network but disables stale actions',async()=>{
  for(const failure of [new ScanHttpError(503,'SCANNER_UNAVAILABLE'),new TypeError('Failed to fetch')]) {
    const running:ScanStatus={...completed,state:'running',percent:23,perCheck:{secret:null}};
    // Keep real QueryClient cache across unmount; do not seed data or force a new session.
    const transport=transportFor(running);const view=mount(transport,Infinity);
    await screen.findByRole('progressbar');
    expect(screen.getByRole('button',{name:'Отменить скан'})).toBeEnabled();
    const key=[...scope,'scan',id],session=scanSession();
    expect(view.client.getQueryState(key)?.status).toBe('success');
    expect(view.client.getQueryState(key)?.dataUpdatedAt).toBeGreaterThan(0);
    view.unmount();expect(view.client.getQueryData(key)).toEqual(running);
    vi.mocked(transport.get).mockRejectedValueOnce(failure);
    const remounted=render(view.content());
    await waitFor(()=>expect(view.client.getQueryState(key)?.status).toBe('error'));
    expect(transport.get).toHaveBeenCalledTimes(2);
    expect(scanSession()).toEqual(session);
    expect(view.client.getQueryData(key)).toEqual(running);
    expect(screen.getByRole('group',{name:`Ход сканирования ${id}`})).toBeVisible();
    expect(screen.getByRole('progressbar')).toHaveAttribute('value','23');
    expect(screen.getAllByRole('alert').some(alert=>/последн|устар|не удалось обнов|актуальност/i.test(alert.textContent??''))).toBe(true);
    expectNoStaleMutationActions();expect(transport.cancel).not.toHaveBeenCalled();expect(transport.create).not.toHaveBeenCalled();
    remounted.unmount();
  }
});
it.each([401,403] as const)('background%s hides cached report instead of applying recoverable stale fallback',async status=>{
  const transport=transportFor(completed);const view=mount(transport);await screen.findByText('Строка 7');
  vi.mocked(transport.get).mockRejectedValueOnce(new ScanAccessError(status));
  await act(async()=>{await view.client.invalidateQueries({queryKey:[...scope,'scan',id]});});
  await waitFor(()=>expectNoPrivateData());expect(view.client.getQueryData([...scope,'scan',id])).toEqual(completed);expectNoStaleMutationActions();
});
it('owner/session replacement hides old snapshot and ignores late old-owner success',async()=>{
  const transport=transportFor(completed);const view=mount(transport);await screen.findByText('Строка 7');
  let finish!:(value:ScanStatus)=>void;
  vi.mocked(transport.get).mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve;})).mockRejectedValueOnce(new ScanAccessError(403));
  await act(async()=>{void view.client.invalidateQueries({queryKey:[...scope,'scan',id]});});
  await waitFor(()=>expect(finish).toBeTypeOf('function'));
  const next:LiveContext['scope']=['live-scans',55,'different-owner'];
  act(()=>{transitionScanSession(next[2],view.client,true);view.rerender(view.content(next));});
  await waitFor(()=>expect(transport.get).toHaveBeenCalledTimes(3));
  await act(async()=>finish(completed));expectNoPrivateData();expectNoStaleMutationActions();
});
it('mismatched scanId/digest/platform status is not treated as recoverable stale network failure',async()=>{
  for(const patch of [{scanId:'00000000-0000-4000-8000-000000000058'},{digest:`sha256:${'b'.repeat(64)}`},{platform:'linux/arm64'}]) {
    const transport=transportFor(completed);const view=mount(transport);await screen.findByText('Строка 7');
    vi.mocked(transport.get).mockResolvedValueOnce({...completed,...patch});
    await act(async()=>{await view.client.invalidateQueries({queryKey:[...scope,'scan',id]});});
    await waitFor(()=>expectNoPrivateData());expectNoStaleMutationActions();view.unmount();
  }
});
it('coverage details preserve OS/node incomplete evidence or explicit unavailable despite overall checked vuln',async()=>{
  for(const evidence of [{os:{outcome:'unsupported' as const,reason:'OS_UNKNOWN' as const},node:{outcome:'unsupported' as const,reason:'NODE_INVENTORY_UNKNOWN' as const}},{}]) {
    const status:ScanStatus={...completed,checks:['vuln'],perCheck:{vuln:{check:'vuln',coverage:'image',outcome:'checked',findingCount:0,...evidence}}};
    const transport=transportFor(status);const view=mount(transport);
    const summary=await screen.findByText('Подробности · что удалось проверить',{selector:'summary'});fireEvent.click(summary);
    const list=screen.getByRole('list',{name:'Исходы проверок'}),tile=within(list).getByRole('listitem');
    expect(tile).toHaveAttribute('data-outcome','checked');
    const subcoverage=screen.getByRole('region',{name:'Покрытие системных пакетов и пакетов приложения'});
    expect(subcoverage.closest('details')).toBe(summary.closest('details'));
    const entries=within(subcoverage).getAllByRole('listitem');expect(entries).toHaveLength(2);
    expect(entries[0]).toHaveTextContent('Системные пакеты');
    expect(entries[1]).toHaveTextContent('Пакеты приложения (Node/npm)');
    if('os' in evidence) {
      expect(entries[0]).toHaveTextContent('Операционная система не определена');expect(entries[1]).toHaveTextContent('Состав пакетов Node.js не определён');
    } else for(const entry of entries) expect(entry).toHaveTextContent('Нет данных о покрытии; отсутствие уязвимостей не подтверждено.');
    view.unmount();
  }
});
it('partial-demo count and SBOM outcome match detail/list/endpoint; demo never fabricates checked zero',async()=>{
  const status=await fixtureScanTransport.get('partial-demo'),list=await fixtureScanTransport.list(),results=await fixtureScanTransport.results('partial-demo'),sbom=await fixtureScanTransport.sbom('partial-demo');
  const secret=results.coverage.find(item=>item.check==='Secrets'),inventory=results.coverage.find(item=>item.check==='SBOM');
  expect(secret).toMatchObject({status:'checked',findingCount:results.findings.filter(item=>item.category==='secret').length});
  expect(status.perCheck?.secret).toMatchObject({outcome:'checked',findingCount:secret?.findingCount});
  expect(list.find(item=>item.scanId==='partial-demo')?.perCheck?.secret?.findingCount).toBe(secret?.findingCount);
  expect(sbom.outcome).toBe('failed');expect(inventory?.status).toBe(sbom.outcome);expect(status.perCheck?.sbom?.outcome).toBe(sbom.outcome);
});
