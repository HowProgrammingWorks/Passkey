const guestView = document.querySelector('#guest-view');
const sessionView = document.querySelector('#session-view');
const createPanel = document.querySelector('#create-panel');
const signinPanel = document.querySelector('#signin-panel');
const createForm = document.querySelector('#create-form');
const usernameInput = document.querySelector('#username');
const loginBtn = document.querySelector('#login-btn');
const logoutBtn = document.querySelector('#logout-btn');
const modeButtons = [...document.querySelectorAll('.mode-btn')];
const sessionName = document.querySelector('#session-name');
const sessionAvatar = document.querySelector('#session-avatar');
const statusEl = document.querySelector('#status');

let currentMode = 'create';
let busy = false;

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

const interactiveControls = () => [
  ...modeButtons,
  createForm.querySelector('button'),
  usernameInput,
  loginBtn,
  logoutBtn,
];

const setBusy = (nextBusy) => {
  busy = nextBusy;
  guestView.dataset.busy = String(nextBusy);
  sessionView.dataset.busy = String(nextBusy);
  for (const control of interactiveControls()) {
    if (!control || control.hidden) continue;
    control.disabled = nextBusy;
  }
};

const setMode = (mode, { focus = true } = {}) => {
  currentMode = mode;
  const createSelected = mode === 'create';

  for (const button of modeButtons) {
    const selected = button.dataset.mode === mode;
    button.setAttribute('aria-selected', String(selected));
    button.tabIndex = selected ? 0 : -1;
  }

  createPanel.hidden = !createSelected;
  signinPanel.hidden = createSelected;

  if (focus && createSelected && !busy) {
    usernameInput.focus();
  }
};

const showSession = (user) => {
  const signedIn = Boolean(user);
  guestView.hidden = signedIn;
  sessionView.hidden = !signedIn;

  if (user) {
    sessionName.textContent = user.username;
    sessionAvatar.textContent = user.username.slice(0, 1).toUpperCase();
    setStatus(`Welcome back, ${user.username}`, 'ok');
  } else {
    sessionName.textContent = '';
    sessionAvatar.textContent = '?';
    setMode(currentMode, { focus: false });
  }
};

const createPasskey = async (event) => {
  event.preventDefault();
  const username = new FormData(createForm).get('username')?.trim();
  if (!username) {
    setStatus('Enter a username to register.', 'error');
    usernameInput.focus();
    return;
  }

  setBusy(true);
  try {
    requireLocalhost();
    setStatus('Creating passkey…', 'pending');
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
    showSession(result.user);
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
    setStatus('Waiting for passkey…', 'pending');
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
    showSession(result.user);
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
    showSession(null);
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
    guestView.hidden = true;
    sessionView.hidden = true;
    return;
  }
  try {
    const result = await api('/api/session');
    showSession(result.user);
  } catch {
    showSession(null);
    setStatus('Ready', 'idle');
  }
};

const onModeKeydown = (event) => {
  const keys = ['ArrowLeft', 'ArrowRight', 'Home', 'End'];
  if (!keys.includes(event.key)) return;

  event.preventDefault();
  const index = modeButtons.indexOf(event.currentTarget);
  let next = index;
  if (event.key === 'ArrowRight') next = (index + 1) % modeButtons.length;
  if (event.key === 'ArrowLeft') {
    next = (index - 1 + modeButtons.length) % modeButtons.length;
  }
  if (event.key === 'Home') next = 0;
  if (event.key === 'End') next = modeButtons.length - 1;

  const mode = modeButtons[next].dataset.mode;
  setMode(mode);
  modeButtons[next].focus();
};

for (const button of modeButtons) {
  button.addEventListener('click', () => {
    if (busy) return;
    setMode(button.dataset.mode);
  });
  button.addEventListener('keydown', onModeKeydown);
}

createForm.addEventListener('submit', createPasskey);
loginBtn.addEventListener('click', loginWithPasskey);
logoutBtn.addEventListener('click', logout);
setMode('create', { focus: false });
restoreSession();
