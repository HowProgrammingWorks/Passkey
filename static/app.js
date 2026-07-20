const registerForm = document.querySelector('#register-form');
const enrollButton = document.querySelector('#enroll');
const authenticateButton = document.querySelector('#authenticate');
const logoutButton = document.querySelector('#logout');
const authDivider = document.querySelector('#auth-divider');
const status = document.querySelector('#status');
const STORAGE_KEY = 'passkey.credentials';
const actionButtons = () => [
  registerForm.querySelector('button'),
  enrollButton,
  authenticateButton,
  logoutButton,
];

const encode = (value) =>
  new Uint8Array(value).toBase64({ alphabet: 'base64url', omitPadding: true });

const decode = (value) =>
  Uint8Array.fromBase64(value, { alphabet: 'base64url' });

const assertLocalhost = () => {
  if (location.hostname !== 'localhost') {
    throw new Error('Open http://localhost:8000 (not 127.0.0.1) for WebAuthn.');
  }
};

const webauthnMessage = (error) => {
  if (error?.name === 'NotAllowedError') {
    return 'Passkey cancelled, timed out, or unavailable for this site.';
  }
  return error.message;
};

const readLocalCredentials = () => {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
  } catch {
    return {};
  }
};

const saveLocalCredential = (record) => {
  const all = readLocalCredentials();
  all[record.id] = record;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(all));
};

const request = async (url, body) => {
  const response = await fetch(url, {
    method: body === undefined ? 'GET' : 'POST',
    credentials: 'same-origin',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Request failed');
  return result;
};

const setStatus = (message, tone = 'idle') => {
  status.value = message;
  status.dataset.tone = tone;
  status.style.animation = 'none';
  status.offsetHeight;
  status.style.animation = '';
};

const setBusy = (busy) => {
  for (const button of actionButtons()) {
    if (button && !button.hidden) button.disabled = busy;
  }
  const input = registerForm.querySelector('input');
  if (input && !registerForm.hidden) input.disabled = busy;
};

const setAuthenticated = (user) => {
  registerForm.hidden = Boolean(user);
  enrollButton.hidden = Boolean(user);
  authenticateButton.hidden = Boolean(user);
  authDivider.hidden = Boolean(user);
  logoutButton.hidden = !user;
  if (user) setStatus(`Signed in as ${user.username}`, 'ok');
};

const register = async (event) => {
  event.preventDefault();
  setBusy(true);
  try {
    assertLocalhost();
    setStatus('Creating passkey...', 'pending');
    const username = new FormData(registerForm).get('username');
    const options = await request('/api/register/options', { username });
    const userId = options.user.id;
    options.challenge = decode(options.challenge);
    options.user.id = decode(userId);
    const credential = await navigator.credentials.create({
      publicKey: options,
    });
    const publicKey = encode(credential.response.getPublicKey());
    const result = await request('/api/register/verify', {
      id: credential.id,
      type: credential.type,
      response: {
        clientDataJSON: encode(credential.response.clientDataJSON),
        authenticatorData: encode(credential.response.getAuthenticatorData()),
        publicKey,
        publicKeyAlgorithm: credential.response.getPublicKeyAlgorithm(),
      },
    });
    saveLocalCredential({
      id: credential.id,
      username: result.user.username,
      userId,
      publicKey,
    });
    setStatus(`Passkey created for ${result.user.username}`, 'ok');
    registerForm.reset();
  } catch (error) {
    setStatus(webauthnMessage(error), 'error');
  } finally {
    setBusy(false);
  }
};

const enroll = async () => {
  setBusy(true);
  try {
    assertLocalhost();
    setStatus('Select a passkey to register...', 'pending');
    const options = await request('/api/register/enroll/options', {});
    options.challenge = decode(options.challenge);
    const credential = await navigator.credentials.get({ publicKey: options });
    const local = readLocalCredentials()[credential.id];
    if (!local) {
      throw new Error(
        'No local public key for this passkey. ' +
          'Create passkey once in this browser first.',
      );
    }
    const result = await request('/api/register/enroll', {
      id: credential.id,
      type: credential.type,
      username: local.username,
      userId: local.userId,
      publicKey: local.publicKey,
      response: {
        clientDataJSON: encode(credential.response.clientDataJSON),
        authenticatorData: encode(credential.response.authenticatorData),
        signature: encode(credential.response.signature),
        userHandle: encode(credential.response.userHandle),
      },
    });
    setStatus(`Registered ${result.user.username} on the server`, 'ok');
  } catch (error) {
    setStatus(webauthnMessage(error), 'error');
  } finally {
    setBusy(false);
  }
};

const authenticate = async () => {
  setBusy(true);
  try {
    assertLocalhost();
    setStatus('Waiting for passkey...', 'pending');
    const options = await request('/api/authenticate/options', {});
    options.challenge = decode(options.challenge);
    options.allowCredentials = options.allowCredentials.map((item) => ({
      ...item,
      id: decode(item.id),
    }));
    const credential = await navigator.credentials.get({ publicKey: options });
    const result = await request('/api/authenticate/verify', {
      id: credential.id,
      type: credential.type,
      response: {
        clientDataJSON: encode(credential.response.clientDataJSON),
        authenticatorData: encode(credential.response.authenticatorData),
        signature: encode(credential.response.signature),
        userHandle: encode(credential.response.userHandle),
      },
    });
    setAuthenticated(result.user);
  } catch (error) {
    setStatus(webauthnMessage(error), 'error');
  } finally {
    setBusy(false);
  }
};

const logout = async () => {
  setBusy(true);
  try {
    await request('/api/logout', {});
    setAuthenticated(null);
    setStatus('Signed out', 'idle');
  } catch (error) {
    setStatus(error.message, 'error');
  } finally {
    setBusy(false);
  }
};

const restoreSession = async () => {
  if (!window.PublicKeyCredential) {
    setStatus('This browser does not support WebAuthn.', 'error');
    registerForm.hidden = true;
    enrollButton.hidden = true;
    authenticateButton.hidden = true;
    authDivider.hidden = true;
    return;
  }
  try {
    const result = await request('/api/session');
    setAuthenticated(result.user);
  } catch {
    setAuthenticated(null);
    setStatus('Ready', 'idle');
  }
};

registerForm.addEventListener('submit', register);
enrollButton.addEventListener('click', enroll);
authenticateButton.addEventListener('click', authenticate);
logoutButton.addEventListener('click', logout);
restoreSession();
