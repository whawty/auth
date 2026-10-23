// User view: the account of the logged in user.

import * as api from './api.js';
import { h, icon, toast } from './dom.js';
import { dateTime, relativeTime } from './format.js';
import { openPasswordDialog } from './password.js';
import * as session from './session.js';

// renderAccountView fills root with the account of the logged in user.
// state is the login state, see session.js.
export function renderAccountView(root, state) {
  const changed = h('dd', { id: 'account-changed' });

  function renderChanged() {
    changed.replaceChildren(
      h('time', { datetime: state.lastchanged.toISOString() }, dateTime(state.lastchanged)),
      h('small', {}, relativeTime(state.lastchanged)));
  }

  async function changePassword() {
    const ok = await openPasswordDialog({
      username: state.username,
      mode: 'own',
      title: 'Change your password',
      submitLabel: 'Change password',
      submit: (password) => api.setPassword(state.session, state.username, password),
    });
    if (ok) {
      state.lastchanged = new Date();
      session.save(state);
      renderChanged();
      toast('Your password has been changed.');
    }
  }

  root.replaceChildren(
    h('div', { class: 'surface' },
      h('dl', { class: 'facts' },
        h('div', {}, h('dt', {}, 'Username'), h('dd', { class: 'mono' }, state.username)),
        h('div', {}, h('dt', {}, 'Role'), h('dd', {}, state.admin ? 'Admin' : 'User')),
        h('div', {}, h('dt', {}, 'Password changed'), changed)),
      h('div', { class: 'surface-foot' },
        h('button', { id: 'change-password', class: 'btn btn-primary', type: 'button', onclick: changePassword },
          icon('key-round'), 'Change password'))));
  renderChanged();
}
