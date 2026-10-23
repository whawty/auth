// whawty.auth web interface

import * as api from './api.js';
import * as session from './session.js';
import { $, h } from './dom.js';
import { renderUsersView } from './users.js';

const descriptions = {
  login: 'Log in to change your password or manage accounts.',
  admin: 'Accounts in this store. Changes apply right away to every service that authenticates against it.',
  user: 'Your account in this store. The password you set here is used by every service that authenticates against it.',
};

// { username, admin, lastchanged, session } of the logged in user, or null
let current = null;

function showView(name) {
  for (const view of ['login', 'admin', 'user']) {
    $(`#view-${view}`).hidden = view !== name;
  }
  $('#page').classList.toggle('narrow', name === 'login');
  $('#description').textContent = descriptions[name];
  $('#session').hidden = name === 'login';
}

/*
 * Views
 */

function renderAdminView() {
  renderUsersView($('#view-admin'), current);
}

// TODO: the account view follows in the next step
function renderUserView() {
  $('#view-user').replaceChildren(h('p', { class: 'surface empty' }, 'Your account will be shown here.'));
}

function enter(state) {
  current = state;
  $('#session-username').textContent = state.username;
  $('#session-admin').hidden = !state.admin;
  if (state.admin) {
    showView('admin');
    renderAdminView();
  } else {
    showView('user');
    renderUserView();
  }
}

/*
 * Login and logout
 */

function setLoginError(message) {
  $('#login-error-text').textContent = message;
  $('#login-error').hidden = !message;
}

function showLogin({ username = '', error = '' } = {}) {
  current = null;
  $('#view-admin').replaceChildren();
  $('#view-user').replaceChildren();
  // a fresh form each time, see handleLogin()
  $('#view-login').replaceChildren($('#login-template').content.cloneNode(true));
  $('#login-form').addEventListener('submit', handleLogin);
  showView('login');
  $('#login-username').value = username;
  setLoginError(error);
  (username ? $('#login-password') : $('#login-username')).focus();
}

async function handleLogin(event) {
  event.preventDefault();

  const username = $('#login-username').value.trim();
  const password = $('#login-password').value;
  if (!username || !password) {
    setLoginError('Enter your username and password.');
    return;
  }

  const button = $('#login-submit');
  button.disabled = true;
  try {
    const state = await api.authenticate(username, password);
    session.save(state);
    // Browsers offer to save the password when the form disappears after a
    // successful request, so remove it instead of just hiding the view.
    $('#login-form').remove();
    enter(state);
  } catch (err) {
    setLoginError(err.status === 401 ? 'The username or password is wrong.' : err.message);
    $('#login-password').value = '';
    $('#login-password').focus();
    button.disabled = false;
  }
}

function handleLogout() {
  session.clear();
  // reload the page so nothing of the previous session stays in memory
  window.location.replace(window.location.pathname);
}

// The web-api rejected the session, i.e. because it timed out.
function handleExpiredSession() {
  if (!current) {
    return;
  }
  const username = current.username;
  session.clear();
  for (const dialog of document.querySelectorAll('dialog[open]')) {
    dialog.close();
  }
  showLogin({ username, error: 'Your session is no longer valid. Please log in again.' });
}

/*
 * Start
 */

$('#logout').addEventListener('click', handleLogout);
api.onUnauthorized(handleExpiredSession);

const saved = session.load();
if (saved) {
  enter(saved);
} else {
  showLogin();
}
