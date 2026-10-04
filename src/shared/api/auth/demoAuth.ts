import { z } from 'zod';

const user = z.object({ id: z.string(), email: z.string().email() });
export type DemoUser = z.infer<typeof user>;

async function authRequest(path: string, options?: RequestInit): Promise<Response> {
  return fetch(`/api/v1/auth/${path}`, {
    ...options,
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    headers: options?.body ? { 'Content-Type': 'application/json' } : undefined,
  });
}

export async function currentDemoUser(signal?: AbortSignal): Promise<DemoUser | null> {
  const response = await authRequest('me', { signal });
  if (response.status === 401) return null;
  if (!response.ok) throw new Error('Не удалось проверить сессию. Попробуйте позже.');
  return user.parse(await response.json());
}

export async function submitDemoCredentials(
  action: 'register' | 'login',
  email: string,
  password: string,
): Promise<DemoUser> {
  const response = await authRequest(action, {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  if (!response.ok) {
    if (response.status === 409) throw new Error('Этот адрес уже зарегистрирован. Войдите в аккаунт.');
    if (response.status === 401) throw new Error('Неверный email или пароль.');
    if (response.status === 429) throw new Error('Слишком много попыток. Попробуйте позже.');
    if (response.status === 400) throw new Error('Проверьте email и пароль (от 12 до 128 байт).');
    throw new Error('Регистрация и вход сейчас недоступны. Демо доступно без аккаунта.');
  }
  return user.parse(await response.json());
}

export async function logoutDemoUser(signal?: AbortSignal): Promise<void> {
  const response = await authRequest('logout', { method: 'POST', body: '{}', signal });
  if (!response.ok) throw new Error('Не удалось выйти. Повторите попытку.');
}
