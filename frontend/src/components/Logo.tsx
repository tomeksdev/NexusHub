// Logo renders the official NexusHub hexagon mark from
// `frontend/public/logo.png`. The asset is a 512×512 image that
// includes the icon AND a "NexusHub" wordmark below it; the sidebar
// only wants the icon. We crop using an SVG <image> viewBox so the
// wordmark is invisible while the icon scales cleanly.
//
// The CROP_* constants below define the rectangle (in source-image
// coordinates) that contains just the hexagon mark. Adjust if the
// asset is replaced.

interface LogoProps {
  size?: number;
  className?: string;
}

// Source rectangle inside logo.png. The asset is 512×512; the
// hexagon icon occupies roughly the upper third, centred. The
// round-7 widening (CROP_X 165→145, CROP_W 185→222) gives both
// sides of the hex breathing room — the previous crop was clipping
// the right edge at sidebar size and made the mark look uneven.
// Operators replacing the asset can re-tune from here.
const CROP_X = 145;
const CROP_Y = 90;
const CROP_W = 222;
const CROP_H = 220;

export function Logo({ size = 32, className }: LogoProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox={`${CROP_X} ${CROP_Y} ${CROP_W} ${CROP_H}`}
      width={size}
      height={(size * CROP_H) / CROP_W}
      role="img"
      aria-label="NexusHub"
      className={className}
      preserveAspectRatio="xMidYMid meet"
    >
      <image
        href="/logo.png"
        x="0"
        y="0"
        width="512"
        height="512"
        preserveAspectRatio="none"
      />
    </svg>
  );
}
