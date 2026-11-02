import { presentImageFailure, type ImageFailureDetail } from '@/shared/api/scans/imageFailure';
import { scanReasonLabel } from './scanProgressPresentation';

type Props = { detail?: ImageFailureDetail; reason?: string | null };

export function ScanCheckFailure({ detail, reason }: Props) {
  const presentation = detail ? presentImageFailure(detail) : null;
  const knownReason = reason ? scanReasonLabel(reason) : null;
  return (
    <div>
      {presentation ? (
        <>
          <p>
            <strong>{presentation.title}.</strong> {presentation.description}
          </p>
          <p>Этап: {presentation.stageLabel}.</p>
          <p>
            <strong>Что сделать.</strong> {presentation.nextStep}
          </p>
        </>
      ) : (
        <>
          <p>
            {knownReason && knownReason !== reason ? knownReason : 'Не удалось выполнить проверку'}. Подробная
            причина не предоставлена.
          </p>
          <p>
            <strong>Что сделать.</strong> Проверьте доступные результаты остальных проверок. Если ошибка
            повторяется, передайте оператору адрес этой проверки.
          </p>
        </>
      )}
    </div>
  );
}
