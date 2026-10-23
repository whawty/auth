// Dialog to set a password, uses <dialog id="password-dialog"> and
// <template id="password-template"> of index.html.
//
// Browsers offer to save or update a password when the form disappears
// after a successful request to the server. That is wanted when users change
// their own password, so in this case the form carries the username in a
// hidden field and is removed afterwards.
//
// When an admin sets the password of somebody else or adds a user, the
// browser must not offer to save that password for the admin's login.
// Chromium also offers that when the form only becomes invisible, so the
// password fields are marked as one-time codes in this case, which browsers
// don't save as passwords. Firefox only reacts to removed forms, so keeping
// the form (it is reused later) is enough there.

import { $, h, icon } from './dom.js';

const strengthLabels = ['Very weak', 'Weak', 'So-so', 'Strong', 'Very strong'];

let zxcvbnLoading = null;

// zxcvbn is big, so it is only loaded when it is needed for the first time.
function loadZxcvbn() {
  if (typeof window.zxcvbn === 'function') {
    return Promise.resolve();
  }
  if (!zxcvbnLoading) {
    zxcvbnLoading = new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = 'vendor/zxcvbn/zxcvbn.js';
      script.onload = resolve;
      script.onerror = () => {
        zxcvbnLoading = null;
        script.remove();
        reject(new Error('zxcvbn could not be loaded'));
      };
      document.head.append(script);
    });
  }
  return zxcvbnLoading;
}

function passwordForm() {
  const dialog = $('#password-dialog');
  let form = $('#password-form', dialog);
  if (!form) {
    dialog.replaceChildren($('#password-template').content.cloneNode(true));
    form = $('#password-form', dialog);
  }
  return form;
}

// openPasswordDialog asks for a new password for username and calls
// submit(password) with it, which returns a promise. The dialog stays open
// and shows the error if that promise is rejected. mode is 'own' if users
// change their own password, 'other' if an admin sets the password of
// another user and 'add' for new users. Resolves to true once the password
// was set, to false if the dialog was closed without setting it.
export function openPasswordDialog({ username, mode, title, submitLabel, submit }) {
  const dialog = $('#password-dialog');
  const form = passwordForm();
  const field = (name) => $(`#password-${name}`, form);
  const newPassword = field('new');
  const retype = field('retype');
  const submitButton = field('submit');

  function setError(message) {
    field('error-text').textContent = message;
    field('error').hidden = !message;
  }

  function updateMatch() {
    const match = field('match');
    const ok = newPassword.value !== '' && newPassword.value === retype.value;
    match.className = 'match';
    match.replaceChildren();
    if (retype.value) {
      match.classList.add(ok ? 'ok' : 'bad');
      match.append(icon(ok ? 'check' : 'x'), ok ? 'Passwords match' : 'Passwords don’t match');
    }
    submitButton.disabled = !ok;
  }

  function updateStrength() {
    const meter = field('meter');
    const label = field('score');
    const hints = field('hints');
    const password = newPassword.value;
    hints.replaceChildren();
    field('crack').textContent = '';
    label.className = '';

    let score = 0;
    if (!password) {
      label.textContent = 'Type a password';
    } else if (typeof window.zxcvbn !== 'function') {
      label.textContent = zxcvbnLoading ? 'Checking strength…' : 'Strength check not available';
    } else {
      const result = window.zxcvbn(password, [username, 'whawty']);
      score = result.score;
      label.className = `score-${score}`;
      label.textContent = strengthLabels[score];
      field('crack').textContent = `estimated crack time: ${result.crack_times_display.offline_slow_hashing_1e4_per_second}`;
      if (result.feedback.warning) {
        hints.append(h('li', { class: 'warning' }, result.feedback.warning));
      }
      for (const suggestion of result.feedback.suggestions) {
        hints.append(h('li', {}, suggestion));
      }
    }
    meter.dataset.score = String(score);
    meter.querySelectorAll('span').forEach((s, i) => s.classList.toggle('on', i < score));
    updateMatch();
  }

  field('title').replaceChildren(...[title].flat());
  field('username').value = mode === 'own' ? username : '';
  for (const input of [newPassword, retype]) {
    input.autocomplete = mode === 'own' ? 'new-password' : 'one-time-code';
  }
  newPassword.value = '';
  retype.value = '';
  submitButton.textContent = submitLabel;
  setError('');
  updateStrength();
  loadZxcvbn().then(updateStrength, updateStrength);

  newPassword.oninput = () => {
    setError('');
    updateStrength();
  };
  retype.oninput = () => {
    setError('');
    updateMatch();
  };
  for (const button of form.querySelectorAll('[data-close]')) {
    button.onclick = () => dialog.close();
  }

  return new Promise((resolve) => {
    let busy = false;

    form.onsubmit = async (event) => {
      event.preventDefault();
      if (busy || submitButton.disabled) {
        return;
      }
      busy = true;
      submitButton.disabled = true;
      try {
        await submit(newPassword.value);
      } catch (err) {
        busy = false;
        if (err.status === 401) {
          dialog.close(); // app.js shows the login again
          return;
        }
        setError(err.message);
        updateMatch();
        newPassword.focus();
        return;
      }
      if (mode === 'own') {
        form.remove(); // lets the browser offer to update the saved password
      }
      dialog.close();
      resolve(true);
    };

    dialog.addEventListener('close', () => {
      // don't keep passwords in the page
      newPassword.value = '';
      retype.value = '';
      resolve(false);
    }, { once: true });

    dialog.showModal();
    newPassword.focus();
  });
}
