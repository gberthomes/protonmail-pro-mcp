// Mail MCP — web interface. Vanilla JS, no build step.
'use strict';

const I18N = {
  en: {
    signOut: 'Sign out', loginTitle: 'Manage your Mail MCP',
    loginText: 'Sign in with your organization account to add mailboxes and connect your AI assistants.',
    signIn: 'Sign in', connectTitle: 'Connect an AI assistant',
    connectText: 'Use this address in your MCP client. Sign-in happens in the browser the first time.',
    copy: 'Copy', copied: 'Copied', otherClients: 'Other clients',
    claude1: 'Open <b>Settings → Connectors</b> in Claude (web, desktop or mobile).',
    claude2: 'Choose <b>Add custom connector</b> and paste the address above.',
    claude3: 'Click <b>Connect</b>, approve and sign in.',
    codeHint: 'Then run /mcp in Claude Code to sign in.',
    gpt1: 'Open <b>Settings → Apps &amp; Connectors</b> and enable developer mode if needed.',
    gpt2: 'Create a connector with the address above and <b>OAuth</b> authentication.',
    sseHint: 'Clients that only support the old SSE transport can use {url}.',
    accountsTitle: 'Mail accounts', accountsText: 'Proton Mail (through Bridge), Gmail, Outlook, iCloud or any IMAP mailbox.',
    addAccount: 'Add account', emptyTitle: 'No mailbox yet',
    empty1: 'Click <b>Add account</b> and enter your address: server settings are detected automatically.',
    empty2: 'Gmail and Outlook: sign in with your provider when available, otherwise use an app password.',
    empty3: 'Proton Mail: keep Proton Mail Bridge running and use the password shown in its <b>Mailbox configuration</b>.',
    emptyNoSelf: 'No mailbox is shared with you yet. Ask your administrator.',
    appsTitle: 'Connected apps', appsText: 'AI clients that signed in with your account.',
    appsEmpty: 'No app connected yet.', revoke: 'Revoke',
    revokeConfirm: 'Disconnect {name}? It will have to sign in again (within the hour for already issued tokens).',
    connectedOn: 'connected {date}',
    fEmail: 'Email address', continue: 'Continue', detecting: 'Detecting the server settings…',
    fName: 'Display name', optional: 'Optional', fUser: 'Username', sameAsEmail: 'Same as email',
    fPass: 'Password', fPassBridge: 'Bridge password', fPassApp: 'App password', keepPass: 'Leave empty to keep the current one',
    passBridge: 'Shown by Proton Mail Bridge (account → Mailbox configuration). It is not your Proton password. Stored encrypted.',
    passApp: 'This provider requires an app-specific password. <a href="{url}" target="_blank" rel="noopener">Create one</a>. Stored encrypted.',
    passGeneric: 'The password of this mailbox (or an app password if two-factor authentication is on). Stored encrypted.',
    fId: 'Identifier', auto: 'Automatic',
    idHint: 'Short name the assistant uses to pick this mailbox, e.g. "perso" or "work".',
    fUsers: 'Who can use this mailbox', usersPlaceholder: 'name@example.com',
    usersHint: 'Emails, *@domain.com or group:name. Press Enter to add.',
    usersGlobal: 'Empty: everyone allowed by MCP_ALLOWED_USERS.',
    advanced: 'Server settings', fProvider: 'Provider', custom: 'Other (IMAP)', bridgeNote: "Uses the server's Proton Mail Bridge.",
    imapHost: 'IMAP server', smtpHost: 'SMTP server', security: 'Security', none: 'None',
    imapUser: 'IMAP login (if different)', smtpUser: 'SMTP login (if different)',
    verifyTls: 'Verify TLS certificates', saveSent: 'Save a copy of sent messages in "Sent"',
    change: 'Change', viaBridge: 'Through Proton Mail Bridge on this server',
    src_preset: 'known provider', src_autoconfig: 'published by the domain', src_ispdb: 'Mozilla ISPDB', src_mx: 'from the MX records',
    src_srv: 'from DNS SRV records', src_autodiscover: 'Microsoft Autodiscover', src_guess: 'guessed, please check', src_none: 'not detected',
    notDetected: 'Settings could not be detected: enter them below.',
    signInWith: 'Sign in with {name}', reconnectWith: 'Reconnect with {name}',
    oauthNote: 'Recommended: no password is stored, access can be revoked from your {name} account.',
    oauthOnlyNote: '{name} requires signing in: passwords are refused for this mailbox.',
    oauthMissing: '{name} sign-in is not configured on this server: use an app password, or ask the administrator to set MAIL_OAUTH_{ENV}_CLIENT_ID.',
    oauthOnlyMissing: '{name} only accepts sign-in with a {name} account, which is not configured on this server. Ask the administrator to set MAIL_OAUTH_{ENV}_CLIENT_ID.',
    usePassword: 'Use a password instead', connectedWith: 'Connected with {name}',
    test: 'Test connection', testing: 'Testing…', cancel: 'Cancel', save: 'Save', saving: 'Saving…', redirecting: 'Redirecting…',
    newAccount: 'Add a mail account', editAccount: 'Edit {email}',
    imapOk: 'Reading mail (IMAP) works', imapBad: 'Reading mail (IMAP) failed',
    smtpOk: 'Sending mail (SMTP) works', smtpBad: 'Sending mail (SMTP) failed',
    saved: 'Account saved', deleted: 'Account deleted', del: 'Delete', edit: 'Edit', mailboxConnected: 'Mailbox connected',
    deleteConfirm: 'Delete {email}? Assistants will no longer be able to use it.',
    fromConfig: 'configuration', shared: 'shared with you', yours: 'yours', connected: 'connected', failed: 'error',
    youAdmin: 'administrator', local: 'local mode', revoked: 'App disconnected',
    errGeneric: 'Something went wrong', errEmail: 'Enter a valid email address',
    forbidden: 'You are not allowed to use this server.'
  },
  fr: {
    signOut: 'Déconnexion', loginTitle: 'Gérer votre MCP mail',
    loginText: 'Connectez-vous avec votre compte pour ajouter des boîtes mail et connecter vos assistants IA.',
    signIn: 'Se connecter', connectTitle: 'Connecter un assistant IA',
    connectText: "Utilisez cette adresse dans votre client MCP. La connexion se fait dans le navigateur la première fois.",
    copy: 'Copier', copied: 'Copié', otherClients: 'Autres',
    claude1: 'Ouvrez <b>Paramètres → Connecteurs</b> dans Claude (web, bureau ou mobile).',
    claude2: 'Choisissez <b>Ajouter un connecteur personnalisé</b> et collez l’adresse ci-dessus.',
    claude3: 'Cliquez sur <b>Connecter</b>, autorisez puis connectez-vous.',
    codeHint: 'Puis lancez /mcp dans Claude Code pour vous connecter.',
    gpt1: 'Ouvrez <b>Paramètres → Applications et connecteurs</b> et activez le mode développeur si besoin.',
    gpt2: 'Créez un connecteur avec l’adresse ci-dessus et l’authentification <b>OAuth</b>.',
    sseHint: 'Les clients qui ne gèrent que l’ancien transport SSE peuvent utiliser {url}.',
    accountsTitle: 'Comptes mail', accountsText: 'Proton Mail (via Bridge), Gmail, Outlook, iCloud ou toute boîte IMAP.',
    addAccount: 'Ajouter un compte', emptyTitle: 'Aucune boîte mail pour l’instant',
    empty1: 'Cliquez sur <b>Ajouter un compte</b> et saisissez votre adresse : les réglages sont détectés automatiquement.',
    empty2: 'Gmail et Outlook : connectez-vous avec votre fournisseur si c’est proposé, sinon utilisez un mot de passe d’application.',
    empty3: 'Proton Mail : laissez Proton Mail Bridge tourner et utilisez le mot de passe de sa <b>Configuration de la boîte mail</b>.',
    emptyNoSelf: 'Aucune boîte mail n’est partagée avec vous. Demandez à votre administrateur.',
    appsTitle: 'Applications connectées', appsText: 'Clients IA connectés avec votre compte.',
    appsEmpty: 'Aucune application connectée.', revoke: 'Révoquer',
    revokeConfirm: 'Déconnecter {name} ? Il devra se reconnecter (sous une heure pour les jetons déjà émis).',
    connectedOn: 'connecté le {date}',
    fEmail: 'Adresse e-mail', continue: 'Continuer', detecting: 'Détection des réglages du serveur…',
    fName: 'Nom affiché', optional: 'Facultatif', fUser: 'Identifiant', sameAsEmail: 'Identique à l’e-mail',
    fPass: 'Mot de passe', fPassBridge: 'Mot de passe Bridge', fPassApp: 'Mot de passe d’application', keepPass: 'Laisser vide pour garder l’actuel',
    passBridge: 'Affiché par Proton Mail Bridge (compte → Configuration de la boîte mail). Ce n’est pas votre mot de passe Proton. Stocké chiffré.',
    passApp: 'Ce fournisseur exige un mot de passe d’application. <a href="{url}" target="_blank" rel="noopener">En créer un</a>. Stocké chiffré.',
    passGeneric: 'Le mot de passe de cette boîte (ou un mot de passe d’application si la double authentification est active). Stocké chiffré.',
    fId: 'Identifiant court', auto: 'Automatique',
    idHint: 'Nom court utilisé par l’assistant pour choisir cette boîte, ex. « perso » ou « pro ».',
    fUsers: 'Qui peut utiliser cette boîte', usersPlaceholder: 'nom@exemple.fr',
    usersHint: 'E-mails, *@domaine.fr ou group:nom. Entrée pour ajouter.',
    usersGlobal: 'Vide : toutes les personnes autorisées par MCP_ALLOWED_USERS.',
    advanced: 'Réglages du serveur', fProvider: 'Fournisseur', custom: 'Autre (IMAP)', bridgeNote: 'Utilise le Proton Mail Bridge du serveur.',
    imapHost: 'Serveur IMAP', smtpHost: 'Serveur SMTP', security: 'Sécurité', none: 'Aucune',
    imapUser: 'Identifiant IMAP (si différent)', smtpUser: 'Identifiant SMTP (si différent)',
    verifyTls: 'Vérifier les certificats TLS', saveSent: 'Enregistrer une copie des messages envoyés dans « Envoyés »',
    change: 'Modifier', viaBridge: 'Via le Proton Mail Bridge de ce serveur',
    src_preset: 'fournisseur connu', src_autoconfig: 'publié par le domaine', src_ispdb: 'base Mozilla ISPDB', src_mx: 'd’après les MX',
    src_srv: 'd’après les enregistrements SRV', src_autodiscover: 'Autodiscover Microsoft', src_guess: 'deviné, à vérifier', src_none: 'non détecté',
    notDetected: 'Les réglages n’ont pas pu être détectés : saisissez-les ci-dessous.',
    signInWith: 'Se connecter avec {name}', reconnectWith: 'Reconnecter avec {name}',
    oauthNote: 'Recommandé : aucun mot de passe stocké, accès révocable depuis votre compte {name}.',
    oauthOnlyNote: '{name} impose la connexion par compte : les mots de passe sont refusés pour cette boîte.',
    oauthMissing: 'La connexion {name} n’est pas configurée sur ce serveur : utilisez un mot de passe d’application, ou demandez à l’administrateur de définir MAIL_OAUTH_{ENV}_CLIENT_ID.',
    oauthOnlyMissing: '{name} n’accepte que la connexion avec un compte {name}, qui n’est pas configurée sur ce serveur. Demandez à l’administrateur de définir MAIL_OAUTH_{ENV}_CLIENT_ID.',
    usePassword: 'Utiliser un mot de passe', connectedWith: 'Connecté avec {name}',
    test: 'Tester la connexion', testing: 'Test en cours…', cancel: 'Annuler', save: 'Enregistrer', saving: 'Enregistrement…', redirecting: 'Redirection…',
    newAccount: 'Ajouter un compte mail', editAccount: 'Modifier {email}',
    imapOk: 'Lecture des mails (IMAP) OK', imapBad: 'Échec de la lecture des mails (IMAP)',
    smtpOk: 'Envoi des mails (SMTP) OK', smtpBad: 'Échec de l’envoi des mails (SMTP)',
    saved: 'Compte enregistré', deleted: 'Compte supprimé', del: 'Supprimer', edit: 'Modifier', mailboxConnected: 'Boîte mail connectée',
    deleteConfirm: 'Supprimer {email} ? Les assistants ne pourront plus l’utiliser.',
    fromConfig: 'configuration', shared: 'partagé avec vous', yours: 'à vous', connected: 'connecté', failed: 'erreur',
    youAdmin: 'administrateur', local: 'mode local', revoked: 'Application déconnectée',
    errGeneric: 'Une erreur est survenue', errEmail: 'Saisissez une adresse e-mail valide',
    forbidden: 'Vous n’êtes pas autorisé à utiliser ce serveur.'
  }
};

const OAUTH_NAMES = { google: 'Google', microsoft: 'Microsoft' };

const lang = (navigator.language || 'en').toLowerCase().startsWith('fr') ? 'fr' : 'en';
const T = I18N[lang];
const t = (key, vars = {}) => (T[key] ?? I18N.en[key] ?? key).replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? '');
const escapeHtml = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const $ = sel => document.querySelector(sel);
const el = (tag, attrs = {}, ...children) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c != null) node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return node;
};
const icon = name => {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'ic');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `#i-${name}`);
  svg.append(use);
  return svg;
};

function applyI18n() {
  document.documentElement.lang = lang;
  // Dictionary strings are trusted and may contain <b>.
  document.querySelectorAll('[data-i18n]').forEach(n => (n.innerHTML = t(n.dataset.i18n)));
  document.querySelectorAll('[data-i18n-placeholder]').forEach(n => (n.placeholder = t(n.dataset.i18nPlaceholder)));
}

function toast(message, bad = false) {
  const node = el('div', { class: `toast${bad ? ' bad' : ''}`, role: bad ? 'alert' : 'status' }, message);
  $('#toasts').append(node);
  setTimeout(() => node.remove(), bad ? 7000 : 3000);
}

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(`/admin/api${path}`, {
    method,
    credentials: 'same-origin',
    headers: { 'x-pmcp': '1', ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || t('errGeneric'));
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

function confirmDialog(text, action) {
  const dlg = $('#confirm');
  $('#confirm-text').textContent = text;
  $('#confirm-yes').textContent = action;
  dlg.returnValue = '';
  dlg.showModal();
  return new Promise(resolve => dlg.addEventListener('close', () => resolve(dlg.returnValue === 'yes'), { once: true }));
}

async function copy(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = el('textarea', {}, text);
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  const label = btn.querySelector('span');
  if (label) {
    label.textContent = t('copied');
    setTimeout(() => (label.textContent = t('copy')), 1500);
  } else toast(t('copied'));
}

async function busy(btn, labelKey, fn) {
  const label = btn.querySelector('span') ?? btn;
  const original = label.innerHTML;
  btn.disabled = true;
  label.textContent = t(labelKey);
  try {
    return await fn();
  } finally {
    btn.disabled = false;
    label.innerHTML = original;
  }
}

// ------------------------------------------------------------------ state

const state = {
  me: null,
  accounts: [],
  status: {},
  editing: null, // account being edited
  users: [],
  discovery: null,
  mode: 'password', // 'password' | 'oauth'
  oauthProvider: null
};

const provider = id => state.me.providers.find(p => p.id === id);

async function boot() {
  applyI18n();
  document.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', () => copy($(b.dataset.copy).textContent, b)));
  document.querySelectorAll('#client-tabs [role="tab"]').forEach(tab =>
    tab.addEventListener('click', () => {
      document.querySelectorAll('#client-tabs [role="tab"]').forEach(x => x.setAttribute('aria-selected', String(x === tab)));
      document.querySelectorAll('.tab-panel').forEach(p => (p.hidden = p.id !== `tab-${tab.dataset.tab}`));
    })
  );
  $('#logout').addEventListener('click', logout);
  $('#add-account').addEventListener('click', () => openEditor());
  $('#discover-btn').addEventListener('click', runDiscovery);
  $('#change-servers').addEventListener('click', () => {
    $('#advanced').open = true;
    $('#advanced').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  });
  $('#use-password').addEventListener('click', () => setMode('password'));
  $('#oauth-btn').addEventListener('click', startOAuth);
  $('#provider-select').addEventListener('change', e => applyPreset(e.target.value, true));
  $('#test-btn').addEventListener('click', testFromForm);
  $('#save-btn').addEventListener('click', save);
  const form = $('#account-form');
  form.addEventListener('submit', e => {
    if (e.submitter?.value === 'cancel') return;
    e.preventDefault();
  });
  form.email.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !$('#step-email').hidden && !state.editing) {
      e.preventDefault();
      runDiscovery();
    }
  });
  $('#users-input').addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      addUser(e.target.value);
      e.target.value = '';
    } else if (e.key === 'Backspace' && !e.target.value && state.users.length) {
      state.users.pop();
      renderChips();
    }
  });
  $('#users-input').addEventListener('blur', e => {
    if (e.target.value.trim()) {
      addUser(e.target.value);
      e.target.value = '';
    }
  });

  try {
    state.me = await api('/me');
  } catch (err) {
    $('#loading').hidden = true;
    $('#app').removeAttribute('aria-busy');
    $('#login').hidden = false;
    if (err.status === 403) {
      $('#login-error').textContent = t('forbidden');
      $('#login-error').hidden = false;
    }
    if (err.status === 401 && !err.data?.login) $('#login-btn').hidden = true;
    return;
  }
  renderShell();
  fillProviderSelect();
  await Promise.all([loadAccounts(), loadApps()]);
  $('#loading').hidden = true;
  $('#app').removeAttribute('aria-busy');
  $('#dash').hidden = false;
  handleReturn();
}

/** Back from "Sign in with Google/Microsoft". */
function handleReturn() {
  const params = new URLSearchParams(location.search);
  const connected = params.get('connected');
  const error = params.get('error');
  if (connected || error) history.replaceState(null, '', '/admin');
  if (error) toast(error, true);
  if (connected) {
    toast(t('mailboxConnected'));
    const account = state.accounts.find(a => a.id === connected);
    if (account) testSaved(account);
  }
}

function renderShell() {
  const { me } = state;
  $('#user').hidden = false;
  $('#logout').hidden = me.local;
  const role = me.local ? t('local') : me.admin ? t('youAdmin') : '';
  $('#who').textContent = [me.user.name || me.user.email || me.user.sub, role && `· ${role}`].filter(Boolean).join(' ');
  $('#mcp-url').textContent = me.mcpUrl;
  $('#snippet-code').textContent = `claude mcp add --transport http mail ${me.mcpUrl}`;
  $('#snippet-json').textContent = JSON.stringify({ mcpServers: { mail: { type: 'http', url: me.mcpUrl } } }, null, 2);
  if (me.sseUrl) {
    $('#sse-hint').textContent = t('sseHint', { url: me.sseUrl });
    $('#sse-hint').hidden = false;
  }
  $('#add-account').hidden = !me.selfService;
  $('#apps-card').hidden = !me.appsSupported;
  $('#foot').textContent = `protonmail-pro-mcp ${me.version}`;
}

function fillProviderSelect() {
  const select = $('#provider-select');
  select.replaceChildren(
    ...state.me.providers.map(p => el('option', { value: p.id }, p.name)),
    el('option', { value: 'custom' }, t('custom'))
  );
}

async function loadAccounts() {
  try {
    state.accounts = (await api('/accounts')).accounts;
  } catch (err) {
    toast(err.message, true);
  }
  renderAccounts();
}

function renderAccounts() {
  $('#accounts').replaceChildren(...state.accounts.map(accountCard));
  $('#accounts-empty').hidden = state.accounts.length > 0;
  $('#accounts-empty .steps').hidden = !state.me.selfService;
  if (!state.me.selfService) $('#accounts-empty b').textContent = t('emptyNoSelf');
}

function accountCard(a) {
  const st = state.status[a.id];
  const badges = [el('span', { class: 'badge accent' }, a.id), el('span', { class: 'badge' }, a.providerName)];
  if (a.auth.startsWith('oauth:')) badges.push(el('span', { class: 'badge' }, OAUTH_NAMES[a.auth.slice(6)] ?? 'OAuth'));
  if (a.source === 'config') badges.push(el('span', { class: 'badge' }, t('fromConfig')));
  else if (a.mine && !state.me.local) badges.push(el('span', { class: 'badge' }, t('yours')));
  else if (!state.me.admin && !a.mine) badges.push(el('span', { class: 'badge' }, t('shared')));
  if (st?.result) {
    const ok = st.result.imap.ok && st.result.smtp.ok;
    badges.push(el('span', { class: `badge ${ok ? 'ok' : 'bad'}` }, ok ? t('connected') : t('failed')));
  }
  if (state.me.admin || a.editable) {
    for (const u of a.users.slice(0, 3)) badges.push(el('span', { class: 'badge' }, u));
    if (a.users.length > 3) badges.push(el('span', { class: 'badge' }, `+${a.users.length - 3}`));
  }
  const errors = st?.result
    ? [st.result.imap, st.result.smtp].filter(r => !r.ok).map(r => r.error).filter((v, i, arr) => v && arr.indexOf(v) === i)
    : [];

  const testBtn = el('button', { class: 'btn sm', type: 'button', onclick: () => testSaved(a) }, icon('plug'), el('span', {}, st?.busy ? t('testing') : t('test')));
  testBtn.disabled = Boolean(st?.busy);
  const actions = [testBtn, el('span', { class: 'spacer' })];
  if (a.editable) {
    actions.push(
      el('button', { class: 'btn sm ghost', type: 'button', onclick: () => openEditor(a), 'aria-label': t('edit') }, icon('edit'), el('span', { class: 'lbl' }, t('edit'))),
      el('button', { class: 'btn sm ghost', type: 'button', onclick: () => remove(a), 'aria-label': t('del') }, icon('trash'))
    );
  }
  return el(
    'article',
    { class: 'acct' },
    el('div', { class: 'acct-top' },
      el('div', { class: 'avatar', 'aria-hidden': 'true' }, (a.displayName || a.email).charAt(0)),
      el('div', { class: 'acct-id' },
        el('div', { class: 'acct-name' }, a.displayName || a.email),
        a.displayName ? el('div', { class: 'acct-mail' }, a.email) : null)),
    el('div', { class: 'badges' }, badges),
    errors.length ? el('div', { class: 'acct-error' }, errors.join(' — ')) : null,
    el('div', { class: 'acct-actions' }, actions)
  );
}

async function testSaved(a) {
  state.status[a.id] = { busy: true };
  renderAccounts();
  try {
    state.status[a.id] = { result: await api('/accounts/test', { method: 'POST', body: { savedId: a.id } }) };
  } catch (err) {
    state.status[a.id] = undefined;
    toast(err.message, true);
  }
  renderAccounts();
}

async function remove(a) {
  if (!(await confirmDialog(t('deleteConfirm', { email: a.email }), t('del')))) return;
  try {
    await api(`/accounts/${encodeURIComponent(a.id)}`, { method: 'DELETE' });
    toast(t('deleted'));
    await loadAccounts();
  } catch (err) {
    toast(err.message, true);
  }
}

// ------------------------------------------------------------------ editor

function addUser(value) {
  const v = value.trim().replace(/,$/, '');
  if (v && !state.users.some(u => u.toLowerCase() === v.toLowerCase())) state.users.push(v);
  renderChips();
}

function renderChips() {
  const own = state.me.ownRule.toLowerCase();
  $('#users-chips').replaceChildren(
    ...state.users.map((u, i) => {
      const locked = !state.me.admin && u.toLowerCase() === own;
      return el('span', { class: 'chip' }, u,
        locked ? null : el('button', { type: 'button', 'aria-label': `Remove ${u}`, onclick: () => { state.users.splice(i, 1); renderChips(); } }, icon('x')));
    })
  );
  $('#users-field .hint').textContent = state.users.length === 0 && state.me.admin ? t('usersGlobal') : t('usersHint');
}

function showFormError(message) {
  $('#form-error').textContent = message || '';
  $('#form-error').hidden = !message;
}

const localPart = email => email.split('@')[0];

/** Fill the server fields from a preset (or leave them for "custom"). */
function applyPreset(id, userChoice = false) {
  const f = $('#account-form');
  f.provider.value = provider(id) ? id : 'custom';
  const p = provider(id);
  const bridge = Boolean(p?.bridge);
  $('#bridge-note').hidden = !bridge;
  $('#servers').hidden = bridge;
  if (p && !bridge && p.imap) {
    const email = f.email.value.trim();
    const login = (s, style) => ((s.username ?? style) === 'localpart' ? localPart(email) : '');
    f.imapHost.value = p.imap.host; f.imapPort.value = p.imap.port; f.imapSecurity.value = p.imap.security;
    f.smtpHost.value = p.smtp.host; f.smtpPort.value = p.smtp.port; f.smtpSecurity.value = p.smtp.security;
    f.imapUser.value = login(p.imap, p.username);
    f.smtpUser.value = login(p.smtp, p.username);
    f.verifyTls.checked = true;
  }
  if (p) f.saveSent.checked = p.saveSent;
  if (userChoice) {
    state.discovery = { ...(state.discovery ?? {}), provider: { id: p?.id ?? 'custom', name: p?.name ?? t('custom') }, source: 'manual', oauth: p?.oauth, oauthSupported: p?.oauth, oauthOnly: p?.oauthOnly, appPasswordUrl: p?.appPasswordUrl, bridge };
    renderDetails();
  }
}

function renderDetails() {
  const d = state.discovery ?? {};
  const f = $('#account-form');
  const editing = state.editing;
  const pid = editing ? editing.provider : d.provider?.id ?? 'custom';
  const p = provider(pid);
  const name = editing ? editing.providerName : d.provider?.name ?? t('custom');
  $('#provider-avatar').textContent = name.charAt(0);
  $('#provider-name').textContent = name;
  const servers = p?.bridge ? t('viaBridge') : f.imapHost.value ? `${f.imapHost.value}:${f.imapPort.value} · ${f.smtpHost.value}:${f.smtpPort.value}` : '';
  const source = !editing && d.source && d.source !== 'manual' ? t(`src_${d.source}`) : '';
  $('#provider-detail').textContent = [servers, source].filter(Boolean).join(' — ');

  // OAuth: offered when the provider supports it and the server is configured.
  const oauthProvider = p?.oauth ?? (editing ? undefined : d.oauth);
  const supported = p?.oauth ? p.oauth : d.oauthSupported;
  const oauthOnly = p?.oauthOnly ?? d.oauthOnly;
  state.oauthProvider = oauthProvider;
  const oauthName = OAUTH_NAMES[supported] ?? '';
  $('#oauth-btn').textContent = editing?.auth.startsWith('oauth:') ? t('reconnectWith', { name: oauthName }) : t('signInWith', { name: oauthName });
  $('#oauth-note').textContent = oauthOnly ? t('oauthOnlyNote', { name: oauthName }) : t('oauthNote', { name: oauthName });
  $('#use-password').hidden = Boolean(oauthOnly);
  const missing = Boolean(supported && !oauthProvider);
  $('#oauth-missing').hidden = !missing;
  $('#oauth-missing').textContent = missing
    ? t(oauthOnly ? 'oauthOnlyMissing' : 'oauthMissing', { name: oauthName, ENV: String(supported).toUpperCase() })
    : '';

  const preferOAuth = Boolean(oauthProvider) && (editing ? editing.auth.startsWith('oauth:') : true);
  setMode(preferOAuth ? 'oauth' : 'password');
  // Passwords are refused by this provider and its sign-in is not configured: nothing can be saved.
  if (missing && oauthOnly && !editing) {
    $('#password-box').hidden = true;
    $('#test-btn').hidden = true;
    $('#save-btn').hidden = true;
  }

  // Password field labels and hints depend on the provider.
  const appUrl = p?.appPasswordUrl ?? d.appPasswordUrl;
  $('#password-label').textContent = p?.bridge ? t('fPassBridge') : appUrl ? t('fPassApp') : t('fPass');
  $('#pass-hint').innerHTML = p?.bridge ? t('passBridge') : appUrl ? t('passApp', { url: escapeHtml(appUrl) }) : t('passGeneric');
  f.password.placeholder = editing && editing.auth === 'password' ? t('keepPass') : '';
}

function setMode(mode) {
  state.mode = mode;
  const oauth = mode === 'oauth' && Boolean(state.oauthProvider);
  $('#oauth-box').hidden = !oauth;
  $('#password-box').hidden = oauth;
  $('#test-btn').hidden = oauth && !(state.editing && state.editing.auth.startsWith('oauth:'));
  // Saving an OAuth mailbox happens on return from the provider (except edits of other fields).
  $('#save-btn').hidden = oauth && !state.editing;
}

function openEditor(a = null) {
  const f = $('#account-form');
  f.reset();
  state.editing = a;
  state.discovery = null;
  state.users = a ? [...a.users] : state.me.local ? [] : [state.me.ownRule];
  $('#editor-title').textContent = a ? t('editAccount', { email: a.email }) : t('newAccount');
  f.email.value = a?.email ?? '';
  f.email.readOnly = false;
  f.displayName.value = a?.displayName ?? '';
  f.username.value = a && a.username !== a.email ? a.username : '';
  f.id.value = a?.id ?? '';
  $('#test-result').hidden = true;
  $('#discover-status').hidden = true;
  showFormError('');
  $('#advanced').open = false;
  if (a) {
    applyPreset(a.provider);
    if (a.imap) {
      f.imapHost.value = a.imap.host; f.imapPort.value = a.imap.port; f.imapSecurity.value = a.imap.security; f.imapUser.value = a.imap.username ?? '';
      f.smtpHost.value = a.smtp.host; f.smtpPort.value = a.smtp.port; f.smtpSecurity.value = a.smtp.security; f.smtpUser.value = a.smtp.username ?? '';
      f.verifyTls.checked = a.imap.verifyTls;
    }
    f.saveSent.checked = a.saveSent;
    $('#step-email').hidden = false;
    $('#discover-btn').hidden = true;
    $('#step-details').hidden = false;
    renderDetails();
  } else {
    $('#discover-btn').hidden = false;
    $('#step-details').hidden = true;
  }
  $('#editor-foot').hidden = !a;
  // Only administrators may relax TLS verification.
  $('#verify-row').hidden = !state.me.admin;
  renderChips();
  $('#editor').showModal();
  (a ? f.displayName : f.email).focus();
}

async function runDiscovery() {
  const f = $('#account-form');
  const email = f.email.value.trim();
  if (!f.email.checkValidity() || !email) {
    showFormError(t('errEmail'));
    f.email.focus();
    return;
  }
  showFormError('');
  $('#discover-status').textContent = t('detecting');
  $('#discover-status').hidden = false;
  await busy($('#discover-btn'), 'detecting', async () => {
    try {
      const d = await api('/discover', { method: 'POST', body: { email } });
      state.discovery = d;
      if (d.found && d.imap) {
        f.provider.value = provider(d.provider.id) ? d.provider.id : 'custom';
        $('#bridge-note').hidden = true;
        $('#servers').hidden = false;
        f.imapHost.value = d.imap.host; f.imapPort.value = d.imap.port; f.imapSecurity.value = d.imap.security;
        f.smtpHost.value = d.smtp?.host ?? ''; f.smtpPort.value = d.smtp?.port ?? 465; f.smtpSecurity.value = d.smtp?.security ?? 'tls';
        f.imapUser.value = d.imap.username !== email ? d.imap.username : '';
        f.smtpUser.value = d.smtp && d.smtp.username !== email ? d.smtp.username : '';
        f.verifyTls.checked = true;
        f.saveSent.checked = d.saveSent;
      } else if (d.bridge) {
        applyPreset('proton-bridge');
      } else {
        applyPreset('custom');
        const domain = email.split('@')[1];
        f.imapHost.value = `imap.${domain}`; f.imapPort.value = 993; f.imapSecurity.value = 'tls';
        f.smtpHost.value = `smtp.${domain}`; f.smtpPort.value = 465; f.smtpSecurity.value = 'tls';
        f.saveSent.checked = true;
        $('#advanced').open = true;
      }
      $('#discover-status').textContent = d.found ? '' : t('notDetected');
      $('#discover-status').hidden = d.found;
      $('#discover-btn').hidden = true;
      $('#step-details').hidden = false;
      $('#editor-foot').hidden = false;
      renderDetails();
      (state.mode === 'oauth' ? $('#oauth-btn') : f.password).focus();
    } catch (err) {
      $('#discover-status').hidden = true;
      showFormError(err.message);
    }
  });
}

function formBody({ forOAuth = false } = {}) {
  const f = $('#account-form');
  const body = {
    email: f.email.value.trim(),
    displayName: f.displayName.value.trim() || undefined,
    username: forOAuth ? undefined : f.username.value.trim() || undefined,
    password: forOAuth || state.mode === 'oauth' ? undefined : f.password.value || undefined,
    id: f.id.value.trim() || undefined,
    users: state.users,
    provider: f.provider.value,
    saveSent: f.saveSent.checked
  };
  if (!provider(body.provider)?.bridge) {
    const verifyTls = f.verifyTls.checked;
    body.imap = { host: f.imapHost.value.trim(), port: Number(f.imapPort.value), security: f.imapSecurity.value, verifyTls, username: f.imapUser.value.trim() || undefined };
    body.smtp = { host: f.smtpHost.value.trim(), port: Number(f.smtpPort.value), security: f.smtpSecurity.value, verifyTls, username: f.smtpUser.value.trim() || undefined };
  }
  return body;
}

function renderTest(result) {
  const row = (ok, okText, badText, error) =>
    el('div', {},
      el('div', { class: 'row' }, el('span', { class: ok ? 'ok' : 'bad' }, icon(ok ? 'check' : 'x')), el('span', {}, ok ? okText : badText)),
      !ok && error ? el('div', { class: 'detail' }, error) : null);
  const box = $('#test-result');
  box.replaceChildren(row(result.imap.ok, t('imapOk'), t('imapBad'), result.imap.error), row(result.smtp.ok, t('smtpOk'), t('smtpBad'), result.smtp.error));
  box.hidden = false;
}

async function testFromForm() {
  showFormError('');
  await busy($('#test-btn'), 'testing', async () => {
    try {
      const result = await api('/accounts/test', { method: 'POST', body: { ...formBody(), savedId: state.editing?.id } });
      renderTest(result);
      if (state.editing) state.status[state.editing.id] = { result };
    } catch (err) {
      showFormError(err.message);
    }
  });
}

async function save() {
  showFormError('');
  await busy($('#save-btn'), 'saving', async () => {
    try {
      const body = formBody();
      if (state.editing) await api(`/accounts/${encodeURIComponent(state.editing.id)}`, { method: 'PUT', body });
      else await api('/accounts', { method: 'POST', body });
      $('#editor').close();
      toast(t('saved'));
      await loadAccounts();
    } catch (err) {
      showFormError(err.message);
    }
  });
}

async function startOAuth() {
  showFormError('');
  await busy($('#oauth-btn'), 'redirecting', async () => {
    try {
      const { url } = await api('/oauth/start', {
        method: 'POST',
        body: { provider: state.oauthProvider, accountId: state.editing?.id, draft: formBody({ forOAuth: true }) }
      });
      location.assign(url);
    } catch (err) {
      showFormError(err.message);
    }
  });
}

// ------------------------------------------------------------------ apps

async function loadApps() {
  if (!state.me.appsSupported) return;
  let apps = [];
  try {
    apps = (await api('/apps')).apps;
  } catch (err) {
    toast(err.message, true);
  }
  const fmt = new Intl.DateTimeFormat(lang, { dateStyle: 'medium' });
  $('#apps').replaceChildren(
    ...apps.map(app => {
      const name = app.clientName || (app.clientId.startsWith('https://') ? new URL(app.clientId).hostname : app.clientId);
      return el('li', {},
        el('div', { class: 'avatar', 'aria-hidden': 'true' }, name.charAt(0)),
        el('div', { class: 'grow' },
          el('div', { class: 'title' }, name),
          app.issuedAt ? el('div', { class: 'muted small' }, t('connectedOn', { date: fmt.format(new Date(app.issuedAt * 1000)) })) : null),
        el('button', { class: 'btn sm', type: 'button', onclick: () => revoke(app, name) }, t('revoke')));
    })
  );
  $('#apps-empty').hidden = apps.length > 0;
}

async function revoke(app, name) {
  if (!(await confirmDialog(t('revokeConfirm', { name }), t('revoke')))) return;
  try {
    await api(`/apps/${encodeURIComponent(app.clientId)}`, { method: 'DELETE' });
    toast(t('revoked'));
    await loadApps();
  } catch (err) {
    toast(err.message, true);
  }
}

async function logout() {
  try {
    await api('/logout', { method: 'POST' });
  } finally {
    location.reload();
  }
}

boot();
