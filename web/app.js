import { ApkError, copyNameSlug, inspectApk, normalizeCopyName, signApk } from './signer.js';

const $ = (id) => document.getElementById(id);
const box = $('box');
const picker = $('picker');
const signButton = $('sign');
const anotherButton = $('another');
const againLink = $('again');
const copyBox = $('copy');
const nameRow = $('copy-name-row');
const nameInput = $('copy-name');
const statusLine = $('status');
const views = { empty: $('view-empty'), ready: $('view-ready'), done: $('view-done') };

const IDLE = 'Nothing is uploaded. Your APK is signed right here in your browser.';

let view = 'empty';  // what the box shows: empty, ready (an APK to sign) or done
let apk = null;      // the File waiting to be signed
let signed = null;   // { url, name, size, copy } of the APK just signed
let busy = false;
let shownPercent = -1;

function formatSize(bytes) {
  return bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${Math.ceil(bytes / 1024)} KB`;
}

// 16 Oct 2026 11:47:48 -> "20261016-114748"
function stamp(time) {
  const pad2 = (n) => String(n).padStart(2, '0');
  return `${time.getFullYear()}${pad2(time.getMonth() + 1)}${pad2(time.getDate())}`
    + `-${pad2(time.getHours())}${pad2(time.getMinutes())}${pad2(time.getSeconds())}`;
}

// Copy names used before, newest first, offered as suggestions. Kept in this browser only.
const NAMES_KEY = 'apk-signer.copy-names';

function savedNames() {
  try {
    const names = JSON.parse(localStorage.getItem(NAMES_KEY) ?? '[]');
    return Array.isArray(names) ? names.filter((name) => typeof name === 'string') : [];
  } catch {
    return [];
  }
}

function showNames(names) {
  $('copy-names').replaceChildren(...names.map((name) => Object.assign(document.createElement('option'), { value: name })));
}

// Names that make the same package are the same copy, so only the latest spelling is kept.
function rememberName(name) {
  const names = [name, ...savedNames().filter((other) => copyNameSlug(other) !== copyNameSlug(name))].slice(0, 10);
  try {
    localStorage.setItem(NAMES_KEY, JSON.stringify(names));
  } catch {
    // not saved: suggestions are only a convenience
  }
  showNames(names);
}

function setStatus(text, isError = false) {
  statusLine.textContent = text;
  statusLine.classList.toggle('error', isError);
}

function render() {
  const done = view === 'done';
  box.dataset.view = view;
  for (const [name, element] of Object.entries(views)) element.hidden = name !== view;
  box.classList.toggle('busy', busy);
  box.tabIndex = done || busy ? -1 : 0;
  box.setAttribute('aria-disabled', String(done || busy));
  box.setAttribute('aria-label', view === 'ready' ? 'Choose a different APK' : 'Choose an APK to sign');
  $('progress').hidden = !busy;
  $('ready-hint').hidden = busy;
  signButton.hidden = done;
  signButton.disabled = busy || view !== 'ready';
  anotherButton.hidden = !done;
  againLink.hidden = !done;
  statusLine.hidden = done;
  copyBox.disabled = busy;
  copyBox.closest('.option').classList.toggle('disabled', busy);
  nameRow.hidden = !copyBox.checked;
  nameInput.disabled = busy;
  if (view === 'ready') {
    $('ready-name').textContent = apk.name;
    $('ready-meta').textContent = formatSize(apk.size);
  }
  if (done) {
    $('done-name').textContent = signed.name;
    $('done-meta').textContent = `${formatSize(signed.size)}  ·  Downloaded`;
    const { copy } = signed;
    $('done-copy').hidden = !copy;
    $('done-copy').textContent = !copy ? ''
      : copy.name ? `Installs as “${copy.label}”, updating any earlier “${copy.name}” copy`
        : `Installs alongside the original as “${copy.label}”`;
  }
}

function describe(error) {
  return error instanceof ApkError ? error.message : `Signing failed: ${error.message}`;
}

function forgetSigned() {
  if (signed) URL.revokeObjectURL(signed.url);
  signed = null;
}

async function select(file) {
  if (busy) return;
  let problem = /\.apk$/i.test(file.name) ? '' : 'That is not an .apk file.';
  if (!problem) {
    try {
      await inspectApk(file);
    } catch (error) {
      problem = describe(error);
    }
  }
  if (problem) {
    if (view === 'done') {  // the finished view has no status line, so go back to the start
      forgetSigned();
      view = 'empty';
      render();
    }
    setStatus(problem, true);
    return;
  }
  forgetSigned();
  apk = file;
  view = 'ready';
  render();
  setStatus('Ready to sign.');
  signButton.focus();
}

function showProgress(fraction) {
  const percent = Math.round(fraction * 100);
  if (percent === shownPercent) return;
  shownPercent = percent;
  $('progress-bar').style.width = `${percent}%`;
  $('progress-label').textContent = `Signing... ${percent}%`;
}

function download() {
  const link = document.createElement('a');
  link.href = signed.url;
  link.download = signed.name;
  document.body.append(link);
  link.click();
  link.remove();
}

async function sign() {
  if (busy || view !== 'ready') return;
  busy = true;
  shownPercent = -1;
  showProgress(0);
  render();
  setStatus('Signing...');
  try {
    const copyAt = copyBox.checked ? new Date() : null;
    const copyName = copyAt ? normalizeCopyName(nameInput.value) : '';
    const result = await signApk(await apk.arrayBuffer(), showProgress, { copyAt, copyName });
    const blob = new Blob([result.apk], { type: 'application/vnd.android.package-archive' });
    const stem = apk.name.replace(/\.apk$/i, '');
    const tag = copyAt ? `-COPY-${copyName ? `${copyNameSlug(copyName)}-` : ''}${stamp(copyAt)}` : '';
    signed = { url: URL.createObjectURL(blob), name: `${stem}${tag}-SIGNED.apk`, size: blob.size, copy: result.copy };
    if (copyName) rememberName(copyName);
    apk = null;
    view = 'done';
    download();
  } catch (error) {
    setStatus(describe(error), true);
  } finally {
    busy = false;
    render();
    (view === 'done' ? anotherButton : signButton).focus();
  }
}

function signAnother() {
  forgetSigned();
  view = 'empty';
  render();
  setStatus(IDLE);
  box.focus();
}

function openPicker() {
  if (!busy && view !== 'done') picker.click();
}

box.addEventListener('click', openPicker);
box.addEventListener('keydown', (event) => {
  if (event.key !== 'Enter' && event.key !== ' ') return;
  event.preventDefault();
  openPicker();
});
picker.addEventListener('change', () => {
  const file = picker.files[0];
  picker.value = '';  // so picking the same file again still fires
  if (file) select(file);
});
signButton.addEventListener('click', sign);
anotherButton.addEventListener('click', signAnother);
copyBox.addEventListener('change', () => {
  render();
  if (copyBox.checked) nameInput.focus();
});
nameInput.addEventListener('keydown', (event) => {
  if (event.key !== 'Enter') return;
  event.preventDefault();
  sign();
});
againLink.addEventListener('click', (event) => {
  event.preventDefault();
  if (signed) download();
});

// The whole page takes drops, so a near miss never makes the browser open the APK instead.
let dragDepth = 0;
const carriesFiles = (event) => Array.from(event.dataTransfer?.types ?? []).includes('Files');
window.addEventListener('dragenter', (event) => {
  if (!carriesFiles(event)) return;
  event.preventDefault();
  dragDepth++;
  box.classList.toggle('over', !busy);
});
window.addEventListener('dragover', (event) => {
  if (!carriesFiles(event)) return;
  event.preventDefault();
  event.dataTransfer.dropEffect = busy ? 'none' : 'copy';
});
window.addEventListener('dragleave', (event) => {
  if (!carriesFiles(event)) return;
  dragDepth = Math.max(0, dragDepth - 1);
  if (dragDepth === 0) box.classList.remove('over');
});
window.addEventListener('drop', (event) => {
  if (!carriesFiles(event)) return;
  event.preventDefault();
  dragDepth = 0;
  box.classList.remove('over');
  const files = Array.from(event.dataTransfer.files);
  const file = files.find((f) => /\.apk$/i.test(f.name)) ?? files[0];
  if (file) select(file);
});

function supported() {
  try {
    new DecompressionStream('deflate-raw');
    new CompressionStream('deflate-raw');
    return Boolean(window.crypto?.subtle);
  } catch {
    return false;
  }
}

showNames(savedNames());
render();
if (supported()) {
  setStatus(IDLE);
} else {
  busy = true;  // keeps everything disabled
  render();
  setStatus('This browser cannot sign APKs. Please use a current Chrome, Edge, Firefox or Safari.', true);
}
