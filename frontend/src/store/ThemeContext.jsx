import React, { createContext, useContext, useEffect, useState } from 'react';

const ThemeContext = createContext({ theme: 'dark', toggle: () => {} });

export function useTheme() {
  return useContext(ThemeContext);
}

function initialTheme() {
  try {
    const stored = localStorage.getItem('netmap.theme');
    if (stored === 'dark' || stored === 'light') return stored;
  } catch {
    /* storage unavailable */
  }
  try {
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) return 'dark';
  } catch {
    /* matchMedia unavailable */
  }
  return 'light';
}

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(initialTheme);
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try {
      localStorage.setItem('netmap.theme', theme);
    } catch {
      /* storage unavailable */
    }
  }, [theme]);
  const toggle = () => setTheme((t) => (t === 'dark' ? 'light' : 'dark'));
  return <ThemeContext.Provider value={{ theme, toggle }}>{children}</ThemeContext.Provider>;
}

export function ThemeToggle({ compact }) {
  const { theme, toggle } = useTheme();
  return (
    <button
      className="btn theme-toggle"
      onClick={toggle}
      title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
      aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
      style={compact ? { width: '100%' } : undefined}
    >
      {theme === 'dark' ? '☀ Light' : '🌙 Dark'}
    </button>
  );
}
