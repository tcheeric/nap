export function normalizeAbsoluteUrl(value: string): string {
  return new URL(value).toString();
}

export function exactUrlMatch(left: string, right: string): boolean {
  return normalizeAbsoluteUrl(left) === normalizeAbsoluteUrl(right);
}

