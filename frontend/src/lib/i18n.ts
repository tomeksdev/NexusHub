// Package i18n bootstraps react-i18next with the small set of
// languages NexusHub ships today. Adding a locale is two changes:
// add the JSON file under locales/, import it below, and extend the
// `resources` map — everything else flows from useTranslation().
//
// Keys use dotted namespaces (`nav.peers`, `common.loading`) so page
// modules can pull only what they need and the JSON stays greppable.
// Values in each locale must mirror the English tree exactly; a
// missing key falls back to `lng: fallbackLng`.
//
// Language detection order is localStorage → navigator.language →
// fallback (English). Once a user picks a language the choice is
// remembered across reloads via localStorage.

import i18next from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";

import en from "./locales/en.json";
import pl from "./locales/pl.json";

export const LANGUAGES = ["en", "pl"] as const;
export type Language = (typeof LANGUAGES)[number];

export const LANGUAGE_LABELS: Record<Language, string> = {
  en: "English",
  pl: "Polski",
};

void i18next
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      pl: { translation: pl },
    },
    fallbackLng: "en",
    supportedLngs: LANGUAGES,
    interpolation: { escapeValue: false }, // React already escapes.
    detection: {
      order: ["localStorage", "navigator"],
      lookupLocalStorage: "nexushub.lang",
      caches: ["localStorage"],
    },
  });

export default i18next;
