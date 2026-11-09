import { validChatText } from '@/shared/api/scans/llmChatContract';
import { utf8Bytes } from '@/shared/api/scans/vulnAdvisory';

export const SCAN_CHAT_INPUT_BYTE_LIMIT = 2048;

export function scanChatInputFeedback(value: string): string | null {
  // The shared contract alone decides validity; these checks only explain a rejection.
  if (validChatText(value)) return null;
  if (!value.trim()) return 'Введите текст: одних пробелов или переносов строки недостаточно.';
  const bytes = utf8Bytes(value);
  if (bytes > SCAN_CHAT_INPUT_BYTE_LIMIT)
    return `Текст слишком длинный: ${bytes} из ${SCAN_CHAT_INPUT_BYTE_LIMIT} байт UTF-8. Сократите его минимум на ${bytes - SCAN_CHAT_INPUT_BYTE_LIMIT} байт; черновик не обрезан.`;
  if (/[a-z][a-z0-9+.-]*:\/\/|javascript:|data:|file:|www\./iu.test(value))
    return 'Уберите ссылки и адреса с протоколом. Опишите вопрос обычным текстом.';
  if (/[<>]/u.test(value)) return 'Уберите угловые скобки < и > и HTML-разметку. Markdown без HTML поддерживается.';
  if (
    /\b(?:Bearer|password|api[_-]?key|token|secret)\s*[:=]|\b(?:sk-|sk-or-|AKIA)[A-Za-z0-9_-]+/iu.test(value)
  )
    return 'Уберите конструкции с паролями, токенами и ключами доступа. Не отправляйте секреты в чат.';
  if (/[A-Za-z0-9_+/=-]{40,}/u.test(value))
    return 'Уберите длинные непрерывные последовательности из 40 и более букв латиницы, цифр или символов _ + / = -: они могут содержать ключи или закодированные данные.';
  if (/CANARY/iu.test(value)) return 'Уберите служебный маркер CANARY: такие фрагменты не принимаются.';
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\ud800-\udfff]/u.test(value))
    return 'Уберите управляющие символы, маркеры направления текста или повреждённые символы Unicode. Попробуйте набрать этот фрагмент вручную.';
  return 'Текст не прошёл проверку безопасности. Уберите ссылки, HTML, секреты и служебные символы.';
}
