import { z } from 'zod';

const utf8 = new TextEncoder();
export const PASSWORD_HINT = 'От 12 до 128 байт UTF-8: латинская буква обычно занимает 1 байт, кириллица — 2. Пробелы учитываются.';

export function validAuthPassword(value: string): boolean {
  const bytes = utf8.encode(value).length;
  return bytes >= 12 && bytes <= 128;
}

export function normalizeAuthEmail(value: string): string | null {
  const email = value.trim().toLowerCase();
  return utf8.encode(email).length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : null;
}

export function validResetToken(value: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(value);
}

export const passwordResetStatusSchema = z.discriminatedUnion('available', [
  z.object({ available: z.literal(true), delivery: z.literal('configured') }).strict(),
  z.object({
    available: z.literal(false),
    reason: z.enum(['DELIVERY_NOT_CONFIGURED', 'DELIVERY_CONFIGURATION_INVALID', 'AUTH_UNAVAILABLE']),
    action: z.literal('CONTACT_OPERATOR'),
  }).strict(),
]);
export type PasswordResetStatus = z.infer<typeof passwordResetStatusSchema>;

const errorContracts = {
  INVALID_INPUT: { status: 400, message: 'Проверьте заполненные поля и длину пароля.' },
  INVALID_RESET_TOKEN: { status: 400, message: 'Ссылка недействительна или уже использована. Запросите новую ссылку.' },
  UNAUTHORIZED: { status: 401, message: 'Сессия больше не подтверждена. Проверьте вход в аккаунт.' },
  INVALID_CREDENTIALS: { status: 401, message: 'Текущий пароль не подошёл. Проверьте его и попробуйте снова.' },
  INVALID_ORIGIN: { status: 403, message: 'Сервер не разрешил запрос с этого адреса сайта. Требуется проверка настройки сайта оператором.' },
  INVALID_CONTENT_TYPE: { status: 415, message: 'Сервер отклонил формат запроса. Требуется проверка настройки сайта оператором.' },
  RATE_LIMITED: { status: 429, message: 'Слишком много попыток. Попробуйте позже.' },
  AUTH_UNAVAILABLE: { status: 503, message: 'Сервис аккаунтов временно недоступен.' },
  AUTH_BUSY: { status: 503, message: 'Сервис аккаунтов занят. Попробуйте позже.' },
  PASSWORD_RESET_UNAVAILABLE: { status: 503, message: 'Восстановление недоступно. Оператору сайта нужно проверить настройку восстановления.' },
  PASSWORD_RESET_BUSY: { status: 503, message: 'Сервис восстановления занят. Попробуйте позже.' },
} as const;
type SecurityErrorCode = keyof typeof errorContracts | 'UNKNOWN';
const errorEnvelope = z.object({ errorCode: z.string() }).strict();
const acceptedEnvelope = z.object({ status: z.literal('accepted') }).strict();

export class AuthSecurityError extends Error {
  constructor(
    message: string,
    readonly code: SecurityErrorCode = 'UNKNOWN',
    readonly recheckSession = true,
  ) {
    super(message);
    this.name = 'AuthSecurityError';
  }
}

function uncertainResponse(): AuthSecurityError {
  return new AuthSecurityError('Не удалось подтвердить результат запроса. Он мог выполниться; автоматического повтора не будет.');
}

async function request(path: string, options: RequestInit = {}): Promise<Response> {
  try {
    return await fetch(`/api/v1/auth/${path}`, {
      ...options,
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      headers: options.body ? { 'Content-Type': 'application/json' } : undefined,
    });
  } catch {
    // Never surface fetch/JSON errors that may contain request details.
    throw uncertainResponse();
  }
}

async function rejectResponse(response: Response): Promise<never> {
  const envelope = errorEnvelope.safeParse(await response.json().catch(() => null));
  if (envelope.success && Object.hasOwn(errorContracts, envelope.data.errorCode)) {
    const code = envelope.data.errorCode as keyof typeof errorContracts;
    const contract = errorContracts[code];
    if (response.status === contract.status) {
      throw new AuthSecurityError(contract.message, code, response.status >= 500 || code === 'UNAUTHORIZED');
    }
  }
  throw uncertainResponse();
}

export async function getPasswordResetStatus(signal?: AbortSignal): Promise<PasswordResetStatus> {
  const response = await request('password-reset/status', { signal });
  if (response.status !== 200) return rejectResponse(response);
  const parsed = passwordResetStatusSchema.safeParse(await response.json().catch(() => null));
  if (!parsed.success) throw new AuthSecurityError('Не удалось проверить доступность восстановления.', 'UNKNOWN', false);
  return parsed.data;
}

async function postEmpty(path: 'change-password' | 'revoke-all' | 'password-reset/confirm', body: object): Promise<void> {
  const response = await request(path, { method: 'POST', body: JSON.stringify(body) });
  if (response.status !== 204) await rejectResponse(response);
}

function requirePassword(password: string): void {
  if (!validAuthPassword(password)) throw new AuthSecurityError(PASSWORD_HINT, 'INVALID_INPUT', false);
}

export function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  requirePassword(currentPassword);
  requirePassword(newPassword);
  return postEmpty('change-password', { currentPassword, newPassword });
}

export function revokeAllSessions(currentPassword: string): Promise<void> {
  requirePassword(currentPassword);
  return postEmpty('revoke-all', { currentPassword });
}

export async function requestPasswordReset(value: string): Promise<void> {
  const email = normalizeAuthEmail(value);
  if (!email) throw new AuthSecurityError('Введите корректный email длиной не более 254 байт UTF-8.', 'INVALID_INPUT', false);
  const response = await request('password-reset/request', { method: 'POST', body: JSON.stringify({ email }) });
  if (response.status !== 202) return rejectResponse(response);
  if (!acceptedEnvelope.safeParse(await response.json().catch(() => null)).success) throw uncertainResponse();
}

export function confirmPasswordReset(token: string, newPassword: string): Promise<void> {
  requirePassword(newPassword);
  if (!validResetToken(token)) throw new AuthSecurityError('Откройте действительную ссылку восстановления из письма.', 'INVALID_RESET_TOKEN', false);
  return postEmpty('password-reset/confirm', { token, newPassword });
}

export function securityErrorMessage(error: unknown): string {
  return error instanceof AuthSecurityError ? error.message : uncertainResponse().message;
}

export function shouldRecheckSession(error: unknown): boolean {
  return !(error instanceof AuthSecurityError) || error.recheckSession;
}
