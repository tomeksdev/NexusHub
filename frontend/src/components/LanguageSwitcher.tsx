import { useTranslation } from "react-i18next";

import { LANGUAGES, LANGUAGE_LABELS, type Language } from "../lib/i18n";

// LanguageSwitcher is a compact select wired to i18next.changeLanguage.
// Persistence comes from i18next's localStorage detector config, so
// picking a language here survives reloads without extra plumbing.
export function LanguageSwitcher() {
  const { i18n } = useTranslation();
  const current = (i18n.resolvedLanguage ?? "en") as Language;

  return (
    <label className="block text-xs text-slate-500">
      <span className="sr-only">Language</span>
      <select
        value={current}
        onChange={(e) => void i18n.changeLanguage(e.target.value)}
        className="w-full px-2 py-1 rounded bg-slate-950 border border-slate-800 text-slate-300 text-xs focus-visible:outline-2 focus-visible:outline-indigo-500 focus-visible:outline-offset-1 focus:border-indigo-500"
      >
        {LANGUAGES.map((lng) => (
          <option key={lng} value={lng}>
            {LANGUAGE_LABELS[lng]}
          </option>
        ))}
      </select>
    </label>
  );
}
