import React from 'react';

/* NetMap SVG symbol set — one sprite, referenced everywhere via <Icon/>.
   Line style: 24x24 grid, stroke=currentColor, so icons inherit text color
   in both themes. No emoji, no external assets. */

const SYMBOLS = {
  overview: (
    <>
      <rect x="3" y="3" width="7" height="9" rx="1.5" />
      <rect x="14" y="3" width="7" height="5" rx="1.5" />
      <rect x="14" y="12" width="7" height="9" rx="1.5" />
      <rect x="3" y="16" width="7" height="5" rx="1.5" />
    </>
  ),
  topology: (
    <>
      <circle cx="6" cy="6" r="2.4" />
      <circle cx="18" cy="8" r="2.4" />
      <circle cx="12" cy="18" r="2.4" />
      <path d="M8.2 6.5l7.2 1M6.9 8.2l3.7 7.3M16.5 10.1l-3 5.6" />
    </>
  ),
  devices: (
    <>
      <rect x="3" y="4" width="18" height="12" rx="2" />
      <path d="M9 20h6M12 16v4" />
    </>
  ),
  discovery: (
    <>
      <circle cx="11" cy="11" r="6.5" />
      <path d="M15.8 15.8L21 21" />
    </>
  ),
  risks: (
    <>
      <path d="M12 3.5L21 20H3z" />
      <path d="M12 9.5V14" />
      <path d="M12 17.2v.3" />
    </>
  ),
  services: (
    <>
      <rect x="4" y="4" width="16" height="6.5" rx="1.5" />
      <rect x="4" y="13.5" width="16" height="6.5" rx="1.5" />
      <path d="M7.5 7.2h.5M7.5 16.7h.5" />
    </>
  ),
  history: (
    <>
      <circle cx="12" cy="12" r="8" />
      <path d="M12 7.5V12l3.5 2" />
    </>
  ),
  reports: (
    <>
      <path d="M6 3h8l4 4v14H6z" />
      <path d="M14 3v4h4" />
      <path d="M9 12.5h6M9 16.5h6" />
    </>
  ),
  file: (
    <>
      <path d="M6 3h8l4 4v14H6z" />
      <path d="M14 3v4h4" />
    </>
  ),
  settings: (
    <>
      <path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1" />
      <circle cx="15" cy="6" r="2" />
      <circle cx="9" cy="12" r="2" />
      <circle cx="17" cy="18" r="2" />
    </>
  ),
  executive: (
    <>
      <rect x="6" y="5" width="12" height="16" rx="2" />
      <rect x="9" y="2.8" width="6" height="4" rx="1" />
      <path d="M9.5 12h5M9.5 15.8h5" />
    </>
  ),
  technical: (
    <>
      <path d="M9 8l-4.5 4L9 16" />
      <path d="M15 8l4.5 4L15 16" />
    </>
  ),
  html: (
    <>
      <circle cx="12" cy="12" r="8.2" />
      <path d="M3.8 12h16.4" />
      <path d="M12 3.8c2.5 2.4 3.8 5.1 3.8 8.2s-1.3 5.8-3.8 8.2c-2.5-2.4-3.8-5.1-3.8-8.2S9.5 6.2 12 3.8z" />
    </>
  ),
  sarif: (
    <>
      <path d="M10 3h4" />
      <path d="M10.5 3v5.5L5.2 18a2 2 0 001.8 2.9h10a2 2 0 001.8-2.9L13.5 8.5V3" />
      <path d="M7.8 14.5h8.4" />
    </>
  ),
  cef: (
    <>
      <circle cx="12" cy="11" r="1.6" />
      <path d="M8.8 7.8a4.6 4.6 0 000 6.4M15.2 7.8a4.6 4.6 0 010 6.4M6.2 5.2a8.4 8.4 0 000 11.6M17.8 5.2a8.4 8.4 0 010 11.6" />
      <path d="M12 12.8V21" />
    </>
  ),
  csv: (
    <>
      <rect x="4" y="5" width="16" height="14" rx="1.5" />
      <path d="M4 10h16M4 14.5h16M10.2 10v9M15.5 10v9" />
    </>
  ),
};

export function IconSprite() {
  return (
    <svg width="0" height="0" style={{ position: 'absolute' }} aria-hidden="true" focusable="false">
      <defs>
        {Object.entries(SYMBOLS).map(([name, body]) => (
          <symbol key={name} id={`nm-i-${name}`} viewBox="0 0 24 24">
            {body}
          </symbol>
        ))}
      </defs>
    </svg>
  );
}

export function Icon({ name, size = 18 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <use href={`#nm-i-${name}`} />
    </svg>
  );
}
