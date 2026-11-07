/** Minimal HTML pages for the browser part of the OAuth flow. */

const esc = (s: string) =>
  s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

function layout(title: string, body: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="same-origin"><title>${esc(title)}</title>
<style>
:root{color-scheme:light dark;--bg:#f6f5fb;--card:#fff;--fg:#1c1b22;--muted:#5f5d6b;--accent:#6d4aff;--border:#e3e1ec}
@media (prefers-color-scheme:dark){:root{--bg:#16141c;--card:#211f29;--fg:#ecebf2;--muted:#a19fb0;--border:#34313f}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;padding:16px}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;max-width:460px;width:100%;padding:28px}
h1{font-size:1.25rem;margin:0 0 12px}p{margin:8px 0;color:var(--muted)}strong{color:var(--fg)}code{font-size:.85em;word-break:break-all}
ul{padding-left:20px;color:var(--muted)}.row{display:flex;gap:12px;margin-top:20px}
button{flex:1;padding:11px 14px;border-radius:10px;border:1px solid var(--border);background:transparent;color:var(--fg);font:inherit;cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}.warn{color:#c2410c}
</style></head><body><main class="card">${body}</main></body></html>`;
}

export function consentPage(opts: {
  clientName: string;
  clientId: string;
  redirectHost: string;
  verifiedDomain?: string;
  serverName: string;
  txn: string;
  csrf: string;
}): string {
  const origin = opts.verifiedDomain
    ? `<p>Client identity published by <strong>${esc(opts.verifiedDomain)}</strong>.</p>`
    : `<p class="warn">This client registered itself and its name is not verified.</p>`;
  return layout(
    'Authorize access',
    `<h1>Connect <strong>${esc(opts.clientName)}</strong> to ${esc(opts.serverName)}?</h1>
${origin}
<p>It will be able to read, organize and send email on the mailboxes you are allowed to use.</p>
<ul><li>Redirects to: <code>${esc(opts.redirectHost)}</code></li><li>Client ID: <code>${esc(opts.clientId)}</code></li></ul>
<p>You will sign in with your identity provider next. Only continue if you started this connection.</p>
<form method="post" action="/authorize/consent">
<input type="hidden" name="txn" value="${esc(opts.txn)}"><input type="hidden" name="csrf" value="${esc(opts.csrf)}">
<div class="row"><button type="submit" name="decision" value="deny">Cancel</button>
<button class="primary" type="submit" name="decision" value="approve">Continue</button></div></form>`
  );
}

export function messagePage(title: string, message: string): string {
  return layout(title, `<h1>${esc(title)}</h1><p>${esc(message)}</p>`);
}
