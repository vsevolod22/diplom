import '@testing-library/jest-dom/vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import { DemoAuthPage } from '@/pages/auth/DemoAuthPage';
import { revalidateBrowserSession } from '@/shared/api/auth/revalidateBrowserSession';
import { transitionScanSession } from '@/shared/api/auth/scanSession';

const owner = { id: 'loading-only-owner', email: 'loading-only@example.invalid' };
const clients: QueryClient[] = [];

function response(status: number, body?: object) {
  return new Response(body ? JSON.stringify(body) : null, {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function deferredResponse() {
  let resolve!: (value: Response) => void;
  const promise = new Promise<Response>(done => { resolve = done; });
  return { promise, resolve };
}

function mountAccount(fetchMock: typeof fetch) {
  vi.stubGlobal('fetch', fetchMock);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  clients.push(client);
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/account']}>
        <DemoAuthPage mode="account" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return client;
}

function expectPrivateLoading(message = 'Проверяем сессию…') {
  const region = screen.getByRole('region', { name: 'Проверка входа' });
  expect(region).toBeVisible();
  const status = within(region).getByRole('status');
  expect(status).toHaveTextContent(message);
  expect(status).toHaveAttribute('aria-atomic', 'true');
  expect(within(region).getByText('Данные аккаунта скрыты до успешной проверки.')).toBeVisible();
  expect(screen.queryByText(owner.email)).not.toBeInTheDocument();
  expect(screen.queryByRole('form', { name: 'Смена пароля' })).not.toBeInTheDocument();
  expect(screen.queryByLabelText('Текущий пароль', { exact: true })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Выйти из аккаунта' })).not.toBeInTheDocument();
  expect(region.querySelector('[class*="placeholder"], [class*="skeleton"], [data-slot="skeleton"]')).toBeNull();
}

function onlyMockMe(request: ReturnType<typeof deferredResponse>) {
  return vi.fn<typeof fetch>(async (input, init) => {
    if (String(input) !== '/api/v1/auth/me' || (init?.method ?? 'GET') !== 'GET') {
      throw new Error(`Unexpected request in account loading test: ${String(input)}`);
    }
    return request.promise;
  });
}

afterEach(() => {
  cleanup();
  for (const client of clients.splice(0)) {
    transitionScanSession(null, client, true);
    client.clear();
  }
  vi.unstubAllGlobals();
});

it('account initial loading preserves privacy labels without hidden skeleton placeholders', async () => {
  const request = deferredResponse();
  const fetchMock = onlyMockMe(request);
  mountAccount(fetchMock);
  expectPrivateLoading();

  await act(async () => { request.resolve(response(401)); });

  expect(await screen.findByRole('link', { name: 'Войти' })).toBeVisible();
  expect(screen.getByRole('link', { name: 'Создать аккаунт' })).toBeVisible();
  expect(screen.queryByRole('region', { name: 'Проверка входа' })).not.toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

it('account revalidation hides an existing owner behind placeholder-free privacy status until me resolves', async () => {
  const request = deferredResponse();
  const fetchMock = onlyMockMe(request);
  fetchMock.mockResolvedValueOnce(response(200, owner));
  const client = mountAccount(fetchMock);
  expect(await screen.findByText(owner.email)).toBeVisible();

  let result!: ReturnType<typeof revalidateBrowserSession>;
  act(() => { result = revalidateBrowserSession(client); });
  const settled = result.then(value => ({ value }), error => ({ error }));
  try {
    expectPrivateLoading('Подтверждаем сессию…');
    await waitFor(() => {
      const region = screen.getByRole('region', { name: 'Проверка входа' });
      expect(within(region).getByRole('status')).toHaveTextContent('Проверяем сессию…');
    });
    expectPrivateLoading();
  } finally {
    await act(async () => {
      request.resolve(response(200, owner));
      expect(await settled).toEqual({ value: owner });
    });
  }

  expect(await screen.findByText(owner.email)).toBeVisible();
  expect(screen.queryByRole('region', { name: 'Проверка входа' })).not.toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledTimes(2);
});
