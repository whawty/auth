// Small helpers to build the web interface without a framework.
//
// Everything that comes from the server or the user is added as text, never
// as HTML, so it can't inject markup.

export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

// h creates an element: h('button', { class: 'btn', type: 'button', onclick: fn }, 'Save').
// Attributes with a function value starting with "on" become event listeners,
// false and null attributes are left out, true becomes an empty attribute.
// Children may be nodes, strings, null or (nested) arrays of those.
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) {
      continue;
    }
    if (name.startsWith('on') && typeof value === 'function') {
      el.addEventListener(name.slice(2), value);
    } else if (name === 'class') {
      el.className = value;
    } else {
      el.setAttribute(name, value === true ? '' : String(value));
    }
  }
  el.append(...children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false));
  return el;
}

const svgNS = 'http://www.w3.org/2000/svg';
const sprite = 'vendor/lucide/icons.svg';

// icon returns an <svg> showing an icon of the sprite (see UI_ICONS in the
// Makefile for the available names).
export function icon(name, className = 'icon') {
  const svg = document.createElementNS(svgNS, 'svg');
  svg.setAttribute('class', className);
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  const use = document.createElementNS(svgNS, 'use');
  use.setAttribute('href', `${sprite}#${name}`);
  svg.append(use);
  return svg;
}

function toastContainer() {
  let container = $('.toasts');
  if (!container) {
    container = h('div', { class: 'toasts', 'aria-live': 'polite' });
    document.body.append(container);
  }
  return container;
}

// toast shows a short message at the bottom of the page. Success messages
// disappear after a few seconds, errors stay until they are dismissed.
export function toast(message, { error = false, timeout = 5000 } = {}) {
  const el = h('div', { class: error ? 'toast is-error' : 'toast', role: error ? 'alert' : 'status' },
    icon(error ? 'circle-alert' : 'check'),
    h('span', { class: 'msg' }, message),
    h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Dismiss', onclick: () => el.remove() }, icon('x')));
  toastContainer().append(el);
  if (!error && timeout > 0) {
    setTimeout(() => el.remove(), timeout);
  }
  return el;
}
