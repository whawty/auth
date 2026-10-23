// Admin view: the users of the store.

import * as api from './api.js';
import { confirm } from './dialogs.js';
import { h, icon, toast } from './dom.js';
import { dateTime, relativeTime } from './format.js';
import { openPasswordDialog } from './password.js';

// the same rule as the store uses
const usernameRe = /^[A-Za-z0-9][-_.@A-Za-z0-9]*$/;

const mono = (text) => h('span', { class: 'mono' }, text);

// renderUsersView fills root with the user list. state is the login state
// of the admin, see session.js.
export function renderUsersView(root, state) {
  let users = null; // as returned by api.listUsers(), null until loaded
  let loadError = '';

  const count = h('span', { class: 'count' });
  const filter = h('input', {
    id: 'user-filter', class: 'field', type: 'search', placeholder: 'Filter',
    autocomplete: 'off', spellcheck: 'false', oninput: render,
  });
  const list = h('ul', { id: 'user-list', class: 'rows' });
  const newName = h('input', {
    id: 'add-name', class: 'field', type: 'text', placeholder: 'New username', 'aria-label': 'New username',
    autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false',
  });
  const addAsAdmin = h('input', { type: 'radio', name: 'add-role', id: 'add-role-admin', value: 'admin' });
  const addForm = h('form', { id: 'add-form', class: 'row add-row', novalidate: true, onsubmit: addUser },
    h('span', { class: 'monogram', 'aria-hidden': 'true' }, icon('user-plus')),
    h('div', { class: 'add-form' },
      newName,
      h('fieldset', { class: 'segmented' },
        h('legend', { class: 'visually-hidden' }, 'Role'),
        h('input', { type: 'radio', name: 'add-role', id: 'add-role-user', value: 'user', checked: true }),
        h('label', { for: 'add-role-user' }, 'User'),
        addAsAdmin,
        h('label', { for: 'add-role-admin' }, 'Admin')),
      h('button', { class: 'btn', type: 'submit' }, 'Add user')));

  root.replaceChildren(
    h('div', { class: 'section-head' },
      h('h2', { class: 'section-title' }, 'Users ', count),
      h('label', { class: 'filter' },
        h('span', { class: 'visually-hidden' }, 'Filter users'), icon('search'), filter)),
    h('div', { class: 'surface' }, addForm, list));

  async function load() {
    try {
      users = await api.listUsers(state.session);
      loadError = '';
    } catch (err) {
      if (err.status === 401) {
        return; // app.js shows the login again
      }
      loadError = err.message;
    }
    render();
  }

  // reload reloads the list and moves the focus to the button with the
  // given data-key in the new list.
  async function reload(focusKey) {
    await load();
    const again = focusKey && list.querySelector(`[data-key="${CSS.escape(focusKey)}"]`);
    if (again) {
      again.focus();
    }
  }

  // run performs an action triggered by button and reloads the list
  // afterwards. The focus returns to the same button of the new list.
  async function run(button, action, successMessage) {
    const focusKey = document.activeElement === button ? button.dataset.key : null;
    button.disabled = true;
    try {
      await action();
      if (successMessage) {
        toast(successMessage);
      }
    } catch (err) {
      if (err.status !== 401) {
        toast(err.message, { error: true });
      }
    }
    await reload(focusKey);
    button.disabled = false; // in case the list could not be rendered again
  }

  async function addUser(event) {
    event.preventDefault();
    const name = newName.value.trim();
    let problem = '';
    if (!name) {
      problem = 'Enter the name of the new user.';
    } else if (!usernameRe.test(name)) {
      problem = 'A username starts with a letter or a digit and may only contain letters, digits and the characters - _ . @';
    } else if (users && users[name]) {
      problem = `There already is a user called ${name}.`;
    }
    if (problem) {
      toast(problem, { error: true });
      newName.focus();
      return;
    }

    const admin = addAsAdmin.checked;
    const added = await openPasswordDialog({
      username: name,
      mode: 'add',
      title: [admin ? 'Add admin ' : 'Add user ', mono(name)],
      submitLabel: 'Add user',
      submit: (password) => api.addUser(state.session, name, password, admin),
    });
    if (added) {
      newName.value = '';
      toast(`Added ${name}.`);
      await load();
    }
  }

  function actionButton(name, action, { label, iconName, danger = false, onclick }) {
    return h('button', {
      class: danger ? 'icon-btn is-danger' : 'icon-btn', type: 'button',
      title: label, 'aria-label': `${label}: ${name}`, 'data-key': `${action}:${name}`, onclick,
    }, icon(iconName));
  }

  function userRow(name, user) {
    const roleLabel = user.admin ? 'Make regular user' : 'Make admin';
    const setPassword = async (event) => {
      const focusKey = event.currentTarget.dataset.key;
      const changed = await openPasswordDialog({
        username: name,
        mode: name === state.username ? 'own' : 'other',
        title: ['New password for ', mono(name)],
        submitLabel: 'Change password',
        submit: (password) => api.setPassword(state.session, name, password),
      });
      if (changed) {
        toast(`Password for ${name} updated.`);
        await reload(focusKey);
      }
    };
    const toggleRole = (event) => run(event.currentTarget,
      () => api.setAdmin(state.session, name, !user.admin),
      `${name} is now ${user.admin ? 'a regular user' : 'an admin'}.`);
    const remove = async (event) => {
      const button = event.currentTarget;
      const ok = await confirm({
        title: ['Remove ', mono(name), '?'],
        message: 'The account and its password hash are deleted from the store. This can\'t be undone.',
        confirmLabel: 'Remove',
      });
      if (ok) {
        await run(button, () => api.removeUser(state.session, name), `Removed ${name}.`);
      }
    };

    return h('li', { class: 'row is-hoverable', 'data-user': name },
      h('span', { class: user.admin ? 'monogram is-admin' : 'monogram', 'aria-hidden': 'true' }, name[0].toUpperCase()),
      h('div', { class: 'row-name' },
        h('span', {}, name),
        user.admin ? h('span', { class: 'chip chip-accent' }, 'admin') : null),
      h('div', { class: 'row-note' },
        h('time', { datetime: user.lastchanged.toISOString(), title: dateTime(user.lastchanged) },
          `changed ${relativeTime(user.lastchanged)}`),
        h('span', { class: 'sep', 'aria-hidden': 'true' }, '·'),
        h('span', { class: 'mono', title: 'hash format / parameter set' }, `${user.formatid}/${user.paramid}`),
        user.valid ? null : h('span', { class: 'chip chip-danger flag', title: 'The file of this user in the store is not valid' }, 'invalid'),
        user.supported ? null : h('span', { class: 'chip chip-warn flag', title: 'The store does not support this hash format or parameter set' }, 'unsupported')),
      h('div', { class: 'row-actions' },
        actionButton(name, 'role', { label: roleLabel, iconName: user.admin ? 'shield-off' : 'shield', onclick: toggleRole }),
        actionButton(name, 'password', { label: 'Set password', iconName: 'key-round', onclick: setPassword }),
        actionButton(name, 'remove', { label: 'Remove', iconName: 'trash-2', danger: true, onclick: remove })));
  }

  function message(text, ...extra) {
    return h('li', { class: 'empty' }, text, ...extra);
  }

  function render() {
    if (loadError) {
      count.textContent = '';
      list.replaceChildren(message(`The users could not be loaded: ${loadError} `,
        h('button', { class: 'btn btn-sm', type: 'button', onclick: load }, 'Try again')));
      return;
    }
    if (users === null) {
      count.textContent = '';
      list.replaceChildren(message('Loading users…'));
      return;
    }

    const names = Object.keys(users).sort((a, b) => a.localeCompare(b));
    const query = filter.value.trim().toLowerCase();
    const shown = names.filter((name) => name.toLowerCase().includes(query));
    count.textContent = query ? `${shown.length} of ${names.length}` : String(names.length);

    if (names.length === 0) {
      list.replaceChildren(message('There are no users in this store.'));
    } else if (shown.length === 0) {
      list.replaceChildren(message(`No user matches “${filter.value.trim()}”.`));
    } else {
      list.replaceChildren(...shown.map((name) => userRow(name, users[name])));
    }
  }

  render();
  load();
}

