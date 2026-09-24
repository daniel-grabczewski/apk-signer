import { ApkError, inspectApk, signApk } from './signer.js';

const $ = (id) => document.getElementById(id);
const box = $('box');
const picker = $('picker');
const signButton = $('sign');
const anotherButton = $('another');
const againLink = $('again');
const statusLine = $('status');
const views = { empty: $('view-empty'), ready: $('view-ready'), done: $('view-done') };

const IDLE = 'Nothing is uploaded. Your APK is signed right here in your browser.';

let view = 'empty';  // what the box shows: empty, ready (an APK to sign) or done
let apk = null;      // the File waiting to be signed
let signed = null;   // { url, name, size } of the APK just signed
let busy = false;
let shownPercent = -1;

function formatSize(bytes) {
  return bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${Math.ceil(bytes / 1024)} KB`;
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
  if (view === 'ready') {
    $('ready-name').textContent = apk.name;
    $('ready-meta').textContent = formatSize(apk.size);
  }
  if (done) {
    $('done-name').textContent = signed.name;
    $('done-meta').textContent = `${formatSize(signed.size)}  ·  Downloaded`;
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
    const output = await signApk(await apk.arrayBuffer(), showProgress);
    const blob = new Blob([output], { type: 'application/vnd.android.package-archive' });
    signed = { url: URL.createObjectURL(blob), name: `${apk.name.replace(/\.apk$/i, '')}-SIGNED.apk`, size: blob.size };
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

render();
if (supported()) {
  setStatus(IDLE);
} else {
  busy = true;  // keeps everything disabled
  render();
  setStatus('This browser cannot sign APKs. Please use a current Chrome, Edge, Firefox or Safari.', true);
}
