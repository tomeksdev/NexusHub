// Logo is the inline hexagon mark used in the sidebar, login screen,
// and (via /logo.svg) the favicon. Living as a component instead of
// a PNG asset means there's no embedded text to disambiguate from
// the wordmark — the icon is purely a shape, the "NexusHub" string
// is real UI text rendered next to it.
//
// To rebrand: edit this file. Operators who want a custom mark can
// drop a /logo.png in frontend/public/ and reference it with
// `<img src="/logo.png">`, but the default ships with this SVG.

interface LogoProps {
  // size in pixels; defaults to 32. The component scales freely;
  // 28 is what the sidebar uses, 36 the login screen.
  size?: number;
  // accent overrides the fill colour. Defaults to the product
  // accent (--color-accent). Pass "currentColor" to inherit from
  // the surrounding text colour.
  accent?: string;
  className?: string;
}

export function Logo({ size = 32, accent, className }: LogoProps) {
  // The hexagon points are a flat-topped hex inscribed in a 100×100
  // box. Two layered shapes give the mark a sense of depth without
  // needing gradients or filters: an outer ring and an inner solid
  // hex offset slightly. Both keyed off the accent colour so a
  // theme swap is one CSS variable.
  const fill = accent ?? "var(--color-accent, #FF4C4C)";
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 100 100"
      width={size}
      height={size}
      role="img"
      aria-label="NexusHub"
      className={className}
    >
      {/* Outer ring */}
      <polygon
        points="50,4 92,28 92,72 50,96 8,72 8,28"
        fill="none"
        stroke={fill}
        strokeWidth={5}
        strokeLinejoin="round"
      />
      {/* Inner solid hex */}
      <polygon
        points="50,22 78,38 78,62 50,78 22,62 22,38"
        fill={fill}
        opacity={0.95}
      />
      {/* Inner cutout — gives the hex a "node" feel rather than a flat tile */}
      <polygon
        points="50,38 65,46 65,54 50,62 35,54 35,46"
        fill="#0d0d0d"
      />
    </svg>
  );
}
