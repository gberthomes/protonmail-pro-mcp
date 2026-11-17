/**
 * Network guards against SSRF: anything the server connects to on behalf of a
 * user-supplied address (metadata documents, autodiscovery, user-added mail
 * servers) must resolve to public addresses only.
 */

import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

export function isPrivateAddress(ip: string): boolean {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number) as [number, number];
    return (
      a === 10 ||
      a === 127 ||
      a === 0 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    );
  }
  const v6 = ip.toLowerCase();
  if (v6 === '::1' || v6 === '::') return true;
  if (v6.startsWith('::ffff:')) return isPrivateAddress(v6.slice(7));
  return v6.startsWith('fc') || v6.startsWith('fd') || v6.startsWith('fe80') || v6.startsWith('ff');
}

/** Resolve a host and return its addresses, refusing any non-public one. */
export async function resolvePublic(hostname: string): Promise<string[]> {
  const host = hostname.replace(/^\[|\]$/g, '');
  const addrs = isIP(host) ? [host] : (await lookup(host, { all: true })).map(a => a.address);
  if (addrs.length === 0 || addrs.some(isPrivateAddress)) {
    throw new Error(`${hostname} resolves to a private or reserved address`);
  }
  return addrs;
}

export async function isPublicHost(hostname: string): Promise<boolean> {
  try {
    await resolvePublic(hostname);
    return true;
  } catch {
    return false;
  }
}
