/**
 * OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document),
 * the registration mechanism preferred by MCP 2026-07-28 (DCR is deprecated).
 *
 * The client_id is an HTTPS URL; the authorization server fetches the JSON
 * document behind it. Fetching arbitrary URLs is an SSRF vector, so the fetch
 * is HTTPS-only, refuses private/loopback addresses, follows no redirects,
 * is size- and time-bounded, and results are cached.
 */

import { resolvePublic } from '../net.js';
import type { RegisteredClient } from './store.js';
import { TtlMap } from './store.js';

const MAX_BYTES = 64 * 1024;
const TIMEOUT_MS = 5_000;
const CACHE_SECONDS = 3600;

const cache = new TtlMap<RegisteredClient>(1000);

export function isMetadataDocumentClientId(clientId: string): boolean {
  if (!clientId.startsWith('https://')) return false;
  try {
    const u = new URL(clientId);
    return u.protocol === 'https:' && u.pathname !== '/' && !u.hash && !u.username && !u.password;
  } catch {
    return false;
  }
}

export async function fetchClientMetadataDocument(clientId: string, allowedHosts: string[] = []): Promise<RegisteredClient> {
  const cached = cache.get(clientId);
  if (cached) return cached;

  const url = new URL(clientId);
  if (allowedHosts.length > 0 && !allowedHosts.includes(url.hostname)) {
    throw new Error(`client_id host ${url.hostname} is not allowed`);
  }
  await resolvePublic(url.hostname);

  const res = await fetch(url, {
    redirect: 'error',
    signal: AbortSignal.timeout(TIMEOUT_MS),
    headers: { accept: 'application/json' }
  });
  if (!res.ok) throw new Error(`client metadata document returned HTTP ${res.status}`);
  const len = Number(res.headers.get('content-length') ?? 0);
  if (len > MAX_BYTES) throw new Error('client metadata document too large');
  const body = await res.text();
  if (body.length > MAX_BYTES) throw new Error('client metadata document too large');

  const doc = JSON.parse(body) as Record<string, unknown>;
  if (doc.client_id !== clientId) throw new Error('client metadata document client_id does not match its URL');
  const redirectUris = doc.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0 || !redirectUris.every(u => typeof u === 'string' && URL.canParse(u))) {
    throw new Error('client metadata document must list redirect_uris');
  }
  const authMethod = typeof doc.token_endpoint_auth_method === 'string' ? doc.token_endpoint_auth_method : 'none';
  if (authMethod !== 'none') {
    // Shared secrets are meaningless for metadata-document clients; private_key_jwt is not supported here.
    throw new Error(`token_endpoint_auth_method "${authMethod}" is not supported for metadata document clients (use "none")`);
  }

  const client: RegisteredClient = {
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris: redirectUris as string[],
    client_name: typeof doc.client_name === 'string' ? doc.client_name.slice(0, 200) : undefined,
    client_uri: typeof doc.client_uri === 'string' ? doc.client_uri : undefined,
    logo_uri: typeof doc.logo_uri === 'string' ? doc.logo_uri : undefined,
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    application_type: doc.application_type === 'native' ? 'native' : 'web',
    metadata_document: true
  };
  cache.set(clientId, client, CACHE_SECONDS);
  return client;
}
