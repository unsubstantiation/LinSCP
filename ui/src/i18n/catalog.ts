export type LocaleCode = 'de' | 'en' | 'es' | 'fr';

export interface UnifiedLocaleFile {
  cli: Record<string, string>;
  gui: Record<string, string>;
}

const SUPPORTED: readonly LocaleCode[] = ['de', 'en', 'es', 'fr'];

export function normalizeLocale(raw: string | null | undefined): LocaleCode {
  if (!raw) {
    return 'en';
  }
  const cleaned = raw.split(/[.@]/)[0]?.trim().replace(/-/g, '_') ?? '';
  if (!cleaned) {
    return 'en';
  }
  const lower = cleaned.toLowerCase();
  for (const code of SUPPORTED) {
    if (code === lower) {
      return code;
    }
  }
  const base = lower.split('_')[0] ?? '';
  for (const code of SUPPORTED) {
    if (code === base) {
      return code;
    }
  }
  return 'en';
}

export function interpolate(
  template: string,
  values?: Record<string, string | number>,
): string {
  if (!values) {
    return template;
  }
  return template.replace(/\{([a-z]+)\}/g, (whole, key: string) => {
    if (Object.prototype.hasOwnProperty.call(values, key)) {
      return String(values[key]);
    }
    return whole;
  });
}

export class I18nCatalog {
  private readonly bundles: Record<LocaleCode, Record<string, string>>;
  private active: LocaleCode = 'en';

  public constructor(bundles: Record<LocaleCode, Record<string, string>>) {
    this.bundles = bundles;
  }

  public get locale(): LocaleCode {
    return this.active;
  }

  public setLocale(locale: string): LocaleCode {
    this.active = normalizeLocale(locale);
    return this.active;
  }

  public t(key: string, values?: Record<string, string | number>): string {
    const table = this.bundles[this.active];
    const template = table?.[key] ?? key;
    return interpolate(template, values);
  }

  public tn(
    singular: string,
    plural: string,
    count: number,
    values?: Record<string, string | number>,
  ): string {
    const isOne = this.active === 'fr' ? count === 0 || count === 1 : count === 1;
    const chosen = isOne ? singular : plural;
    return this.t(chosen, { ...values, count });
  }
}
