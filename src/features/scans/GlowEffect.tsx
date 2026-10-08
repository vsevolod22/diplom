// Static adaptation of Motion Primitives GlowEffect (MIT); docs/notices/motion-primitives.md.
// TASK28 removes its animation API; current ScanScene does not use a glow layer.
type GlowEffectProps = {
  colors: string[];
  blur?: 'soft' | 'strong';
};

export function GlowEffect({ colors, blur = 'soft' }: GlowEffectProps) {
  return (
    <div
      data-scan-glow="static"
      aria-hidden="true"
      className={`scan-a1__glow-effect ${blur === 'strong' ? 'scan-a1__glow-effect--strong' : ''}`}
      style={{ background: `linear-gradient(to right, ${colors.join(', ')})` }}
    />
  );
}
