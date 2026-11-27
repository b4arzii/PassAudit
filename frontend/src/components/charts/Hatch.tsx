import { CHART_COLOR } from './chartColors.ts';

/** An SVG pattern of diagonal stripes; reference it as `fill="url(#id)"`. */
export function HatchPattern({ id, color = CHART_COLOR.danger }: { id: string; color?: string }) {
  return (
    <pattern
      id={id}
      width="6"
      height="6"
      patternUnits="userSpaceOnUse"
      patternTransform="rotate(45)"
    >
      <rect width="6" height="6" fill={color} fillOpacity="0.28" />
      <rect width="3" height="6" fill={color} />
    </pattern>
  );
}

/** A tiny legend swatch (solid or hatched). */
export function Swatch({
  color,
  hatched = false,
  className = 'size-3',
}: {
  color: string;
  hatched?: boolean;
  className?: string;
}) {
  if (hatched) {
    return (
      <span
        aria-hidden="true"
        className={`${className} inline-block shrink-0 rounded-sm`}
        style={{
          backgroundImage: `repeating-linear-gradient(45deg, ${color} 0 2px, transparent 2px 4px)`,
          backgroundColor: 'rgb(var(--danger) / 0.28)',
        }}
      />
    );
  }
  return (
    <span
      aria-hidden="true"
      className={`${className} inline-block shrink-0 rounded-sm`}
      style={{ backgroundColor: color }}
    />
  );
}
