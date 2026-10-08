import { Box, FileText, ScanLine } from 'lucide-react';

type ScanSceneProps = {
  variant: 'list' | 'create' | 'detail';
  className?: string;
};

const sceneCopy = {
  list: {
    code: '01 / КАТАЛОГ',
    title: 'У каждой цели —',
    emphasis: 'свой контекст.',
    target: 'Образ',
    scope: 'Область проверки',
    rows: ['Проверки', 'Ограничения'],
    report: 'Факты и причины',
  },
  create: {
    code: '02 / ГРАНИЦЫ',
    title: 'Сначала',
    emphasis: 'границы.',
    target: 'Цель проверки',
    scope: 'Область доверия',
    rows: ['Образ', 'Доступ'],
    report: 'После проверки',
  },
  detail: {
    code: '03 / ДОКАЗАТЕЛЬСТВА',
    title: 'Читать',
    emphasis: 'по существу.',
    target: 'Контекст',
    scope: 'Покрытие',
    rows: ['Проверки', 'Причины'],
    report: 'Факты, не обещания',
  },
};

// A reading diagram, never a scan snapshot. Facts and controls live outside this hidden artwork.
export function ScanScene({ variant, className = '' }: ScanSceneProps) {
  const copy = sceneCopy[variant];
  return (
    <div aria-hidden="true" className={`scan-a1__scene scan-a1__scene--${variant} ${className}`}>
      <div data-scan-scene-art={variant} className="scan-a1__passport">
        <div className="scan-a1__passport-caption">
          <span>{copy.code}</span>
          <span>СИГНАЛ</span>
        </div>
        <div className="scan-a1__passport-flow">
          <div className="scan-a1__passport-target">
            <span className="scan-a1__passport-label">
              <Box size={16} /> 01 / Цель
            </span>
            <span className="scan-a1__passport-title">
              {copy.title}
              <strong>{copy.emphasis}</strong>
            </span>
            <span className="scan-a1__passport-note">{copy.target}</span>
          </div>
          <div className="scan-a1__passport-scope">
            <span className="scan-a1__passport-label">
              <ScanLine size={16} /> 02 / {copy.scope}
            </span>
            <div className="scan-a1__passport-rows">
              {copy.rows.map((row) => (
                <div key={row}>
                  <span>{row}</span>
                  <span className="scan-a1__passport-rule" />
                </div>
              ))}
            </div>
          </div>
          <div className="scan-a1__passport-report">
            <span className="scan-a1__passport-label">
              <FileText size={16} /> 03 / Отчёт
            </span>
            <span className="scan-a1__passport-note">{copy.report}</span>
          </div>
        </div>
        <span className="scan-a1__passport-footer">Схема чтения · не результат</span>
      </div>
    </div>
  );
}
