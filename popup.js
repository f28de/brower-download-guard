/**
 * popup 界面逻辑
 * 所有内容均通过 textContent 写入，避免文件名等外部数据造成 HTML 注入。
 */

import { fmtBytes, fmtRelative, shortHash, copyText, hostOf } from './lib/util.js';
import { SITES } from './lib/sites.js';
import { getSettings, DEFAULT_SETTINGS } from './lib/settings.js';

const COPY_SVG =
  '<svg viewBox="0 0 24 24" width="13" height="13" aria-hidden="true"><path fill="currentColor" d="M16 1H4a2 2 0 0 0-2 2v14h2V3h12V1Zm3 4H8a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2Zm0 16H8V7h11v14Z"/></svg>';

const state = {
  records: [],
  settings: { ...DEFAULT_SETTINGS },
  filter: 'all',
  canReadOrigins: false,
};

const cardMap = new Map();
const focusId = new URLSearchParams(location.search).get('focus');

/* ------------------------------------------------------------------ *
 * DOM 小工具
 * ------------------------------------------------------------------ */

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === null || v === undefined) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else if (k === 'style') Object.assign(node.style, v);
    else if (k.startsWith('on') && typeof v === 'function') {
      node.addEventListener(k.slice(2).toLowerCase(), v);
    } else node.setAttribute(k, v);
  }
  for (const c of children) node.append(c);
  return node;
}

function iconBtn(cls, title, svg) {
  const b = el('button', { class: cls, title, type: 'button' });
  b.innerHTML = svg;
  return b;
}

/* ------------------------------------------------------------------ *
 * Toast
 * ------------------------------------------------------------------ */

let toastTimer = null;
function toast(msg) {
  const node = document.getElementById('toast');
  node.textContent = msg;
  node.hidden = false;
  requestAnimationFrame(() => node.classList.add('show'));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    node.classList.remove('show');
    setTimeout(() => {
      node.hidden = true;
    }, 200);
  }, 1800);
}

/* ------------------------------------------------------------------ *
 * 与后台通信
 * ------------------------------------------------------------------ */

let markSeenTimer = null;
function scheduleMarkSeen() {
  if (markSeenTimer) return;
  markSeenTimer = setTimeout(() => {
    markSeenTimer = null;
    send('markSeen').catch(() => {});
  }, 400);
}

async function send(type, payload = {}) {
  let res;
  try {
    res = await chrome.runtime.sendMessage({ type, ...payload });
  } catch (e) {
    throw new Error('后台服务无响应，请重新加载扩展');
  }
  if (!res) throw new Error('后台服务无响应，请重新加载扩展');
  if (!res.ok) throw new Error(res.error || '操作失败');
  return res;
}

/* ------------------------------------------------------------------ *
 * 状态文案
 * ------------------------------------------------------------------ */

function statusInfo(rec) {
  const busyStatuses = ['pending', 'hashing', 'querying', 'uploading', 'analyzing'];
  const busy = busyStatuses.includes(rec.status);

  switch (rec.status) {
    case 'pending':
      return { v: 'busy', text: '等待处理…', busy, indeterminate: true };
    case 'hashing': {
      const p = rec.progress || {};
      const pct = p.total ? Math.min(100, Math.round((p.loaded / p.total) * 100)) : null;
      return {
        v: 'busy',
        text: pct !== null ? `正在计算哈希 ${pct}%` : `正在计算哈希 ${fmtBytes(p.loaded || 0)}`,
        busy,
        progress: pct,
        indeterminate: pct === null,
      };
    }
    case 'querying':
      return { v: 'busy', text: '正在查询 VirusTotal…', busy, indeterminate: true };
    case 'uploading':
      return { v: 'busy', text: '正在上传到 VirusTotal…', busy, indeterminate: true };
    case 'analyzing':
      return { v: 'busy', text: '引擎分析中，请稍候…', busy, indeterminate: true };
    case 'no_key':
      return { v: 'gray', text: '已计算哈希 · 未配置 API Key', busy };
    case 'hash_failed':
      return { v: 'err', text: '哈希计算失败', busy };
    case 'query_failed':
      return { v: 'err', text: '查询失败', busy };
    case 'done':
      return verdictInfo(rec);
    default:
      return { v: 'gray', text: '未知状态', busy };
  }
}

function verdictInfo(rec) {
  const st = rec.stats || {};
  const total = rec.engineTotal || 0;
  switch (rec.verdict) {
    case 'malicious':
      return { v: 'malicious', text: `危险 · ${st.malicious || 0}/${total} 个引擎报毒`, busy: false };
    case 'suspicious':
      return { v: 'suspicious', text: `可疑 · ${st.suspicious || 0}/${total} 个引擎标记可疑`, busy: false };
    case 'clean':
      return { v: 'clean', text: `安全 · 0/${total} 个引擎报毒`, busy: false };
    case 'not_found':
      return { v: 'gray', text: '未收录 · VirusTotal 暂无该文件记录', busy: false };
    default:
      return { v: 'gray', text: '结果未知', busy: false };
  }
}

function detailText(rec) {
  if (rec.error && (rec.status === 'hash_failed' || rec.status === 'query_failed')) {
    return { text: rec.error.message, cls: 'err' };
  }
  if (rec.sizeMismatch) {
    return {
      text: '⚠ 重新读取到的内容大小与本地文件不一致，哈希可能不是该文件的真实值（来源需要登录或链接已失效）',
      cls: 'warn',
    };
  }
  if (rec.crossOriginRedirect && rec.status !== 'hash_failed') {
    return {
      text: '⚠ 该下载经过跨域跳转，文件实际来自其他主机；哈希对应的是跳转后的内容',
      cls: 'warn',
    };
  }
  if (rec.status === 'done' && rec.verdict === 'malicious' && rec.detections?.length) {
    const sample = rec.detections
      .slice(0, 3)
      .map((d) => `${d.engine}: ${d.name}`)
      .join('；');
    return { text: `${rec.threatLabel ? rec.threatLabel + ' · ' : ''}${sample}`, cls: '' };
  }
  if (rec.status === 'done' && rec.verdict === 'not_found') {
    return { text: '可点击「上传查毒」把文件交给 VirusTotal 扫描，或使用下方站点手动送检', cls: '' };
  }
  if (rec.status === 'no_key') {
    return { text: '配置 VirusTotal API Key 后可自动查毒', cls: '' };
  }
  return null;
}

/* ------------------------------------------------------------------ *
 * 卡片渲染
 * ------------------------------------------------------------------ */

function createCard(rec) {
  const fname = el('div', { class: 'fname', title: rec.path || rec.filename });
  const time = el('div', { class: 'time' });
  const meta = el('div', { class: 'meta' });

  const badge = el('div', { class: 'badge' });
  const detail = el('div', { class: 'detail' });

  const bar = el('div', { class: 'progress' }, [el('i')]);

  const md5v = el('div', { class: 'v' });
  const shaV = el('div', { class: 'v' });
  const md5copy = iconBtn('copy-btn', '复制 MD5', COPY_SVG);
  const shacopy = iconBtn('copy-btn', '复制 SHA-256', COPY_SVG);

  md5copy.addEventListener('click', () => doCopy(rec.md5, 'MD5 已复制'));
  shacopy.addEventListener('click', () => doCopy(rec.sha256, 'SHA-256 已复制'));
  md5v.addEventListener('click', () => doCopy(rec.md5, 'MD5 已复制'));
  shaV.addEventListener('click', () => doCopy(rec.sha256, 'SHA-256 已复制'));

  const hashes = el('div', { class: 'hashes' }, [
    el('div', { class: 'hash-row' }, [el('span', { class: 'k', text: 'MD5' }), md5v, md5copy]),
    el('div', { class: 'hash-row' }, [
      el('span', { class: 'k', text: 'SHA-256' }),
      shaV,
      shacopy,
    ]),
  ]);

  const btnRescan = el('button', { class: 'btn', type: 'button', text: '重新扫描' });
  const btnCred = el('button', { class: 'btn', type: 'button', text: '携带登录信息重试' });
  const btnUpload = el('button', { class: 'btn', type: 'button', text: '上传查毒' });
  const btnDelete = el('button', { class: 'btn danger', type: 'button', text: '删除' });

  btnCred.addEventListener('click', async () => {
    const card = btnCred.closest('.card');
    const cur = (card && card._rec) || rec;
    const escalate = cur.credMode !== 'include';

    if (escalate) {
      const ok = confirm(
        '将携带你在该站点的登录 Cookie，重新读取一次这个下载链接。\n\n' +
          '· Cookie 只会发送给该下载源本身\n' +
          '· 一旦该地址发生任何重定向，请求会立即中止，不会把登录信息带到跳转目标\n\n' +
          '确定继续？'
      );
      if (!ok) return;
    }

    try {
      await send('rescan', { id: cur.id, force: true, credentials: escalate });
      toast(escalate ? '已携带登录信息重试' : '已改用无登录模式重试');
    } catch (e) {
      toast(e.message);
    }
  });

  btnRescan.addEventListener('click', async () => {
    try {
      await send('rescan', { id: rec.id, force: true });
      toast('已开始重新扫描');
    } catch (e) {
      toast(e.message);
    }
  });

  btnUpload.addEventListener('click', async () => {
    const ok = confirm(
      `将把「${rec.filename}」的文件内容上传到 VirusTotal 进行深度扫描。\n\n` +
        '上传后文件会保存在 VirusTotal 的样本库中，可能被其他用户和研究人员下载。\n' +
        '如文件包含隐私或敏感信息，请勿上传。\n\n确定继续？'
    );
    if (!ok) return;
    try {
      await send('upload', { id: rec.id });
      toast('已提交，正在分析…');
    } catch (e) {
      toast(e.message);
    }
  });

  btnDelete.addEventListener('click', async () => {
    try {
      await send('delete', { id: rec.id });
    } catch (e) {
      toast(e.message);
    }
  });

  const actions = el('div', { class: 'actions' }, [btnRescan, btnCred, btnUpload, btnDelete]);

  const sitesRow = el('div', { class: 'sites' }, [el('span', { class: 'label', text: '在线送检' })]);
  for (const site of SITES) {
    const b = el('button', { class: 'site', type: 'button', text: site.name, title: site.desc });
    b.addEventListener('click', () => openSite(site, rec));
    sitesRow.append(b);
  }

  const card = el('article', { class: 'card' }, [
    el('div', { class: 'row' }, [fname, time]),
    meta,
    badge,
    detail,
    bar,
    hashes,
    actions,
    sitesRow,
  ]);

  card._refs = {
    fname, time, meta, badge, detail, bar,
    md5v, shaV, md5copy, shacopy,
    btnRescan, btnCred, btnUpload, btnDelete, sitesRow,
  };
  return card;
}

function syncCard(card, rec) {
  card._rec = rec;
  const r = card._refs;
  const info = statusInfo(rec);

  card.dataset.verdict = rec.status === 'done' ? rec.verdict || 'unknown' : '';
  r.fname.textContent = rec.filename;
  r.fname.title = rec.path || rec.filename;
  r.time.textContent = fmtRelative(rec.createdAt);

  const host = hostOf(rec.finalUrl || rec.url);
  const bits = [fmtBytes(rec.fileSize)];
  if (host) bits.push(host);
  if (rec.mime && rec.mime !== 'application/octet-stream') bits.push(rec.mime);
  r.meta.textContent = bits.join(' · ');

  r.badge.dataset.v = info.v;
  r.badge.textContent = info.text;

  const d = detailText(rec);
  if (d) {
    r.detail.textContent = d.text;
    r.detail.className = `detail ${d.cls}`.trim();
    r.detail.hidden = false;
  } else {
    r.detail.hidden = true;
  }

  // 进度条
  if (info.busy) {
    r.bar.hidden = false;
    if (info.indeterminate || info.progress === null || info.progress === undefined) {
      r.bar.classList.add('indeterminate');
      r.bar.firstChild.style.width = '';
    } else {
      r.bar.classList.remove('indeterminate');
      r.bar.firstChild.style.width = `${info.progress}%`;
    }
  } else {
    r.bar.hidden = true;
  }

  // 哈希
  r.md5v.textContent = rec.md5 || '尚未计算';
  r.md5v.title = rec.md5 || '';
  r.md5v.style.cursor = rec.md5 ? 'pointer' : 'default';
  r.md5copy.disabled = !rec.md5;
  r.shaV.textContent = rec.sha256 || '尚未计算';
  r.shaV.title = rec.sha256 || '';
  r.shaV.style.cursor = rec.sha256 ? 'pointer' : 'default';
  r.shacopy.disabled = !rec.sha256;

  // 按钮可用性
  r.btnRescan.disabled = info.busy;

  // 读取失败时提供凭据模式切换（失败后可来回切换，不会卡死）
  const canToggleCred =
    rec.status === 'hash_failed' && rec.error && rec.error.code === 'fetch_failed';
  r.btnCred.hidden = !canToggleCred;
  r.btnCred.disabled = info.busy;
  r.btnCred.textContent = rec.credMode === 'include' ? '改用无登录模式重试' : '携带登录信息重试';
  const canUpload =
    !!state.settings.apiKey &&
    !!rec.sha256 &&
    !info.busy &&
    ['done', 'no_key', 'hash_failed', 'query_failed'].includes(rec.status) &&
    (rec.fileSize || 0) <= 32 * 1024 * 1024 &&
    (rec.fileSize || 0) > 0;
  r.btnUpload.disabled = !canUpload;
  r.btnUpload.title = canUpload ? '把文件内容上传到 VirusTotal 深度扫描' : '需要先完成哈希计算并配置 API Key（文件需小于 32MB）';

  for (const btn of r.sitesRow.querySelectorAll('.site')) btn.disabled = !rec.sha256;
}

async function doCopy(text, okMsg) {
  if (!text) {
    toast('暂无可复制的内容');
    return;
  }
  const ok = await copyText(text);
  toast(ok ? okMsg : '复制失败，请手动选择文本');
}

function openSite(site, rec) {
  if (!rec.sha256) {
    toast('请先完成哈希计算');
    return;
  }
  const url = site.build(rec.sha256);
  chrome.tabs.create({ url }).catch(() => {});
  if (!site.hashLookup) {
    copyText(rec.sha256).then((ok) => {
      if (ok) toast('SHA-256 已复制，请在站点中粘贴查询');
    });
  }
  window.close();
}

/* ------------------------------------------------------------------ *
 * 列表渲染（按 id 复用 DOM，避免进度刷新时闪烁）
 * ------------------------------------------------------------------ */

function filteredRecords() {
  if (state.filter === 'threat') {
    return state.records.filter((r) => r.verdict === 'malicious' || r.verdict === 'suspicious');
  }
  if (state.filter === 'clean') {
    return state.records.filter((r) => r.verdict === 'clean');
  }
  return state.records;
}

function renderList() {
  const list = document.getElementById('list');
  const records = filteredRecords();
  const ids = new Set(records.map((r) => r.id));

  for (const [id, node] of [...cardMap]) {
    if (!ids.has(id)) {
      node.remove();
      cardMap.delete(id);
    }
  }

  let prev = null;
  for (const rec of records) {
    let card = cardMap.get(rec.id);
    if (!card) {
      card = createCard(rec);
      cardMap.set(rec.id, card);
    }
    syncCard(card, rec);
    const expected = prev ? prev.nextSibling : list.firstChild;
    if (card !== expected) list.insertBefore(card, expected);
    prev = card;
  }

  document.getElementById('empty').hidden = records.length > 0;
}

function renderStats() {
  const all = state.records.length;
  const threat = state.records.filter(
    (r) => r.verdict === 'malicious' || r.verdict === 'suspicious'
  ).length;
  const clean = state.records.filter((r) => r.verdict === 'clean').length;
  const busy = state.records.filter((r) =>
    ['pending', 'hashing', 'querying', 'uploading', 'analyzing'].includes(r.status)
  ).length;

  document.getElementById('c-all').textContent = all;
  document.getElementById('c-threat').textContent = threat;
  document.getElementById('c-clean').textContent = clean;

  const summary = document.getElementById('summary');
  if (all === 0) {
    summary.textContent = '下载完成后自动计算哈希并查毒';
  } else {
    const parts = [`已扫描 ${all} 个文件`];
    if (threat) parts.push(`${threat} 个危险`);
    if (busy) parts.push(`${busy} 个处理中`);
    summary.textContent = parts.join(' · ');
  }
}

function renderNotice() {
  const notice = document.getElementById('notice');
  const text = document.getElementById('notice-text');
  const action = document.getElementById('notice-action');
  action.hidden = true;
  action.onclick = null;

  if (!state.settings.apiKey) {
    notice.hidden = false;
    text.textContent = '未配置 VirusTotal API Key，当前仅计算 MD5 / SHA-256。';
    action.hidden = false;
    action.textContent = '去配置';
    action.onclick = () => {
      chrome.runtime.openOptionsPage();
      window.close();
    };
    return;
  }

  if (!state.canReadOrigins) {
    notice.hidden = false;
    text.textContent = '未授权读取下载来源，无法计算哈希。请在设置页点击「授权」。';
    action.hidden = false;
    action.textContent = '去授权';
    action.onclick = () => {
      chrome.runtime.openOptionsPage();
      window.close();
    };
    return;
  }

  notice.hidden = true;
}

function render() {
  renderStats();
  renderNotice();
  renderList();
}

/* ------------------------------------------------------------------ *
 * 初始化
 * ------------------------------------------------------------------ */

async function init() {
  state.settings = await getSettings();
  const obj = await chrome.storage.local.get('records');
  state.records = Array.isArray(obj.records) ? obj.records : [];
  try {
    state.canReadOrigins = await chrome.permissions.contains({ origins: ['http://*/*', 'https://*/*'] });
  } catch {
    state.canReadOrigins = true;
  }

  render();

  document.getElementById('btn-options').addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
    window.close();
  });

  for (const btn of document.querySelectorAll('#filters .chip')) {
    btn.addEventListener('click', () => {
      state.filter = btn.dataset.filter;
      for (const b of document.querySelectorAll('#filters .chip')) {
        b.classList.toggle('is-active', b === btn);
      }
      renderList();
    });
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (changes.records) {
      state.records = Array.isArray(changes.records.newValue) ? changes.records.newValue : [];
      render();
      // 面板可见时，新结果视为已读，避免角标一直亮着
      if (document.visibilityState === 'visible' && state.records.some((r) => !r.seen)) {
        scheduleMarkSeen();
      }
    }
    if (changes.settings) {
      state.settings = { ...DEFAULT_SETTINGS, ...(changes.settings.newValue || {}) };
      render();
    }
  });

  // 标记已读，清除角标
  send('markSeen').catch(() => {});

  // 从通知跳转过来时定位到对应记录
  if (focusId) {
    requestAnimationFrame(() => {
      const card = cardMap.get(focusId);
      if (card) {
        card.classList.add('is-focus');
        card.scrollIntoView({ block: 'center' });
      }
    });
  }
}

init().catch((e) => {
  document.getElementById('summary').textContent = `初始化失败：${e.message}`;
});
