export function encodeBase64String(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64');
}

export function decodeBase64String(value: string): string {
  return Buffer.from(value, 'base64').toString('utf8');
}

