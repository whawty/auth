// Confirmation dialog, uses the <dialog id="confirm-dialog"> of app.html.

import { $ } from './dom.js';

// confirm asks the user to confirm an action and resolves to true if they
// did. title may be a string or an array of strings and nodes.
export function confirm({ title, message, confirmLabel }) {
  const dialog = $('#confirm-dialog');
  $('#confirm-title').replaceChildren(...[title].flat());
  $('#confirm-text').textContent = message;
  $('#confirm-ok-label').textContent = confirmLabel;
  dialog.returnValue = '';

  return new Promise((resolve) => {
    dialog.addEventListener('close', () => resolve(dialog.returnValue === 'ok'), { once: true });
    dialog.showModal();
    $('#confirm-cancel').focus(); // the harmless choice
  });
}
