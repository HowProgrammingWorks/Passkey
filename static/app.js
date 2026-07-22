const createForm = document.querySelector('#create-form');
const loginBtn = document.querySelector('#login-btn');
const logoutBtn = document.querySelector('#logout-btn');
const guestDivider = document.querySelector('#guest-divider');
const statusEl = document.querySelector('#status');

const toBase64url = (value) => {
  const bytes = new Uint8Array(value);
  return bytes.toBase64({ alphabet: 'base64url', omitPadding: true });
};

const fromBase64url = (value) => {
  const options = { alphabet: 'base64url' };
  return Uint8Array.fromBase64(value, options);
};

const requireLocalhost = () => {
  if (location.hostname !== 'localhost') {
    throw new Error('Open http://localhost:8000 (not 127.0.0.1) for WebAuthn.');
  }
};

const describeError = (error) => {
  if (error?.name === 'NotAllowedError') {
    return 'Passkey cancelled, timed out, or unavailable for this site.';
  }
  return error.message;
};

const api = async (path, body) => {
  const hasBody = body !== undefined;
  const method = hasBody ? 'POST' : 'GET';
  const headers = hasBody ? { 'Content-Type': 'application/json' } : {};
  const payload = hasBody ? JSON.stringify(body) : undefined;
  const options = {
    method,
    credentials: 'same-origin',
    headers,
    body: payload,
  };
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
};

const setStatus = (message, tone = 'idle') => {
  statusEl.value = message;
  statusEl.dataset.tone = tone;
  statusEl.style.animation = 'none';
  statusEl.offsetHeight;
  statusEl.style.animation = '';
};

const setBusy = (busy) => {
  const buttons = [
    createForm.querySelector('button'),
    loginBtn,
    logoutBtn,
  ];
  for (const button of buttons) {
    if (button && !button.hidden) button.disabled = busy;
  }
  const input = createForm.querySelector('input');
  if (input && !createForm.hidden) input.disabled = busy;
};

const showGuest = (user) => {
  const signedIn = Boolean(user);
  createForm.hidden = signedIn;
  guestDivider.hidden = signedIn;
  loginBtn.hidden = signedIn;
  logoutBtn.hidden = !signedIn;
  if (user) setStatus(`Signed in as ${user.username}`, 'ok');
};

const createPasskey = async (event) => {
  event.preventDefault();
  const username = new FormData(createForm).get('username');
  setBusy(true);
  try {
    requireLocalhost();
    setStatus('Creating passkey...', 'pending');
    const options = await api('/api/register/options', { username });
    options.challenge = fromBase64url(options.challenge);
    options.user.id = fromBase64url(options.user.id);
    const createOptions = { publicKey: options };
    const credential = await navigator.credentials.create(createOptions);
    const rawPublicKey = credential.response.getPublicKey();
    if (!rawPublicKey) {
      throw new Error('Authenticator did not return a public key.');
    }
    const { response } = credential;
    const clientDataJSON = toBase64url(response.clientDataJSON);
    const authenticatorData = toBase64url(response.getAuthenticatorData());
    const publicKey = toBase64url(rawPublicKey);
    const publicKeyAlgorithm = response.getPublicKeyAlgorithm();
    const verification = {
      id: credential.id,
      type: credential.type,
      response: {
        clientDataJSON,
        authenticatorData,
        publicKey,
        publicKeyAlgorithm,
      },
    };
    const result = await api('/api/register/verify', verification);
    createForm.reset();
    showGuest(result.user);
    setStatus(`Passkey created — signed in as ${result.user.username}`, 'ok');
  } catch (error) {
    setStatus(describeError(error), 'error');
  } finally {
    setBusy(false);
  }
};

const loginWithPasskey = async () => {
  setBusy(true);
  try {
    requireLocalhost();
    setStatus('Waiting for passkey...', 'pending');
    const options = await api('/api/login/options', {});
    options.challenge = fromBase64url(options.challenge);
    options.allowCredentials = options.allowCredentials.map((item) => {
      const id = fromBase64url(item.id);
      return { ...item, id };
    });
    const getOptions = { publicKey: options };
    const credential = await navigator.credentials.get(getOptions);
    const { response } = credential;
    const clientDataJSON = toBase64url(response.clientDataJSON);
    const authenticatorData = toBase64url(response.authenticatorData);
    const signature = toBase64url(response.signature);
    const userHandle = toBase64url(response.userHandle);
    const verification = {
      id: credential.id,
      type: credential.type,
      response: {
        clientDataJSON,
        authenticatorData,
        signature,
        userHandle,
      },
    };
    const result = await api('/api/login/verify', verification);
    showGuest(result.user);
  } catch (error) {
    setStatus(describeError(error), 'error');
  } finally {
    setBusy(false);
  }
};

const logout = async () => {
  setBusy(true);
  try {
    await api('/api/logout', {});
    showGuest(null);
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
    createForm.hidden = true;
    loginBtn.hidden = true;
    guestDivider.hidden = true;
    return;
  }
  try {
    const result = await api('/api/session');
    showGuest(result.user);
  } catch {
    showGuest(null);
    setStatus('Ready', 'idle');
  }
};

createForm.addEventListener('submit', createPasskey);
loginBtn.addEventListener('click', loginWithPasskey);
logoutBtn.addEventListener('click', logout);
restoreSession();
