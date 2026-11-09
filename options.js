/** 设置页逻辑 */

import { getSettings, saveSettings, DEFAULT_SETTINGS } from './lib/settings.js';
import { fmtDate } from './lib/util.js';

const $ = (id) => document.getElementById(id);

let settings = { ...DEFAULT_SETTINGS };
let saveTimer = null;
let toastTimer = null;

/* ------------------------------------------------------------------ *
 * 提示
 * ------------------------------------------------------------------ */

function toast(msg) {
  const node = $('toast');
  node.textContent = msg;
  node.hidden = false;
  requestAnimationFrame(() => node.classList.add('show'));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    node.classList.remove('show');
    setTimeout(() => {
      node.hidden = true;
    }, 220);
  }, 2200);
}

function flashSaved() {
  const node = $('save-state');
  node.textContent = '已保存';
  node.classList.add('show');
  clearTimeout(flashSaved._t);
  flashSaved._t = setTimeout(() => node.classList.remove('show'), 1600);
}

/* ------------------------------------------------------------------ *
 * 读取表单 → 设置对象
 * ------------------------------------------------------------------ */

/** 解析逗号/空格分隔的主机名列表，只保留合法主机名 */
function parseList(raw) {
  return String(raw || '')
    .split(/[,，\s]+/)
    .map((h) => h.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, ''))
    .filter((h) => /^[a-z0-9.-]+$/.test(h) && h.includes('.'))
    .slice(0, 200);
}

function readForm() {
  const exts = $('excluded')
    .value.split(/[,，\s]+/)
    .map((s) => s.trim().toLowerCase().replace(/^\./, ''))
    .filter((s) => /^[a-z0-9]{1,12}$/.test(s));

  return {
    apiKey: $('api-key').value.trim(),
    autoScan: $('auto-scan').checked,
    maxHashBytes: Number($('max-hash').value) || DEFAULT_SETTINGS.maxHashBytes,
    minIntervalMs: Number($('min-interval').value) || DEFAULT_SETTINGS.minIntervalMs,
    fetchTimeoutMs: Number($('fetch-timeout').value) || DEFAULT_SETTINGS.fetchTimeoutMs,
    allowPrivateHosts: $('allow-private').checked,
    hostBlocklist: parseList($('host-blocklist').value),
    notify: $('notify').checked,
    notifyOnClean: $('notify-clean').checked,
    autoOpenOnThreat: $('auto-open').checked,
    excludedExts: exts,
    keepRecords: Number($('keep-records').value) || DEFAULT_SETTINGS.keepRecords,
  };
}

function writeForm(s) {
  $('api-key').value = s.apiKey || '';
  $('auto-scan').checked = !!s.autoScan;
  $('allow-private').checked = !!s.allowPrivateHosts;
  $('host-blocklist').value = (s.hostBlocklist || []).join(', ');
  $('notify').checked = !!s.notify;
  $('notify-clean').checked = !!s.notifyOnClean;
  $('auto-open').checked = !!s.autoOpenOnThreat;
  $('excluded').value = (s.excludedExts || []).join(', ');

  const corrected = {
    maxHashBytes: setSelect('max-hash', s.maxHashBytes),
    minIntervalMs: setSelect('min-interval', s.minIntervalMs),
    fetchTimeoutMs: setSelect('fetch-timeout', s.fetchTimeoutMs),
    keepRecords: setSelect('keep-records', s.keepRecords),
  };

  updateKeyTag();

  // 存储里的值不在下拉选项内（例如旧版本遗留）时，回写吸附后的值，避免界面与存储不一致
  const changed = Object.keys(corrected).some((k) => Number(s[k]) !== Number(corrected[k]));
  return changed ? corrected : null;
}

/** 选中下拉项；若值不在选项里则吸附到最接近的选项，并返回实际选中的值 */
function setSelect(id, value) {
  const sel = $(id);
  const v = Number(value);
  const values = [...sel.options].map((o) => Number(o.value)).filter((n) => Number.isFinite(n));
  if (values.includes(v)) {
    sel.value = String(v);
    return v;
  }
  const nearest = values.reduce((a, b) => (Math.abs(b - v) < Math.abs(a - v) ? b : a), values[0]);
  sel.value = String(nearest);
  return nearest;
}

function updateKeyTag() {
  const tag = $('key-state');
  const has = $('api-key').value.trim().length > 0;
  tag.textContent = has ? '已配置' : '未配置';
  tag.className = `tag ${has ? 'ok' : ''}`.trim();
}

/* ------------------------------------------------------------------ *
 * 保存
 * ------------------------------------------------------------------ */

function scheduleSave() {
  updateKeyTag();
  clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    settings = await saveSettings(readForm());
    flashSaved();
  }, 350);
}

async function saveNow() {
  clearTimeout(saveTimer);
  settings = await saveSettings(readForm());
  flashSaved();
  return settings;
}

/* ------------------------------------------------------------------ *
 * 权限
 * ------------------------------------------------------------------ */

async function refreshPermState() {
  const tag = $('perm-state');
  let granted = false;
  try {
    granted = await chrome.permissions.contains({ origins: ['http://*/*', 'https://*/*'] });
  } catch {
    granted = false;
  }
  tag.textContent = granted ? '已授权' : '未授权';
  tag.className = `tag ${granted ? 'ok' : 'warn'}`;
  $('btn-grant').disabled = granted;
  $('btn-revoke').disabled = !granted;
}

/* ------------------------------------------------------------------ *
 * 记录统计
 * ------------------------------------------------------------------ */

async function refreshDataState() {
  const obj = await chrome.storage.local.get('records');
  const list = Array.isArray(obj.records) ? obj.records : [];
  $('data-state').textContent = `${list.length} 条记录`;
}

/* ------------------------------------------------------------------ *
 * 初始化
 * ------------------------------------------------------------------ */

async function init() {
  settings = await getSettings();
  const corrected = writeForm(settings);
  if (corrected) settings = await saveSettings(corrected);
  await refreshPermState();
  await refreshDataState();

  $('version').textContent = chrome.runtime.getManifest().version;

  // 所有表单控件变更 → 自动保存
  for (const id of [
    'api-key',
    'auto-scan',
    'allow-private',
    'host-blocklist',
    'max-hash',
    'min-interval',
    'fetch-timeout',
    'notify',
    'notify-clean',
    'auto-open',
    'excluded',
    'keep-records',
  ]) {
    const node = $(id);
    node.addEventListener('change', scheduleSave);
    if (node.tagName === 'INPUT' && (node.type === 'text' || node.type === 'password')) {
      node.addEventListener('input', scheduleSave);
    }
  }

  // 显示 / 隐藏 Key
  $('btn-toggle-key').addEventListener('click', () => {
    const input = $('api-key');
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    $('btn-toggle-key').textContent = show ? '隐藏' : '显示';
  });

  // 验证 Key
  $('btn-verify').addEventListener('click', async () => {
    const key = $('api-key').value.trim();
    const msg = $('key-msg');
    if (!key) {
      msg.textContent = '请先填写 API Key';
      msg.style.color = 'var(--danger)';
      return;
    }
    await saveNow();
    const btn = $('btn-verify');
    btn.disabled = true;
    btn.textContent = '验证中…';
    msg.textContent = '';
    try {
      const res = await chrome.runtime.sendMessage({ type: 'verifyKey', apiKey: key });
      if (res && res.ok) {
        msg.textContent = `✓ ${res.message || 'API Key 可用'}`;
        msg.style.color = 'var(--ok)';
      } else {
        msg.textContent = `✗ ${(res && res.message) || (res && res.error) || '验证失败'}`;
        msg.style.color = 'var(--danger)';
      }
    } catch {
      msg.textContent = '✗ 后台服务无响应，请重新加载扩展';
      msg.style.color = 'var(--danger)';
    } finally {
      btn.disabled = false;
      btn.textContent = '验证 Key';
    }
  });

  // 授权（必须在点击事件里同步调用 request）
  $('btn-grant').addEventListener('click', () => {
    chrome.permissions
      .request({ origins: ['http://*/*', 'https://*/*'] })
      .then(async (granted) => {
        await refreshPermState();
        toast(granted ? '授权成功，可以开始自动查毒了' : '未获得授权，无法计算哈希');
      })
      .catch(() => toast('授权失败，请稍后重试'));
  });

  $('btn-revoke').addEventListener('click', () => {
    chrome.permissions
      .remove({ origins: ['http://*/*', 'https://*/*'] })
      .then(async () => {
        await refreshPermState();
        toast('已撤销授权，后续下载将无法计算哈希');
      })
      .catch(() => toast('撤销失败'));
  });

  // 导出
  $('btn-export').addEventListener('click', async () => {
    const obj = await chrome.storage.local.get('records');
    const list = Array.isArray(obj.records) ? obj.records : [];
    if (list.length === 0) {
      toast('暂无记录可导出');
      return;
    }
    const payload = {
      exportedAt: new Date().toISOString(),
      count: list.length,
      records: list.map((r) => ({
        文件名: r.filename,
        大小: r.fileSize,
        MD5: r.md5,
        'SHA-256': r.sha256,
        结论: r.verdict,
        检出数: r.stats?.malicious ?? null,
        引擎总数: r.engineTotal ?? null,
        威胁名: r.threatLabel ?? null,
        来源: r.finalUrl || r.url,
        下载时间: fmtDate(r.createdAt),
        查询时间: fmtDate(r.checkedAt),
      })),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `download-guard-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    toast(`已导出 ${list.length} 条记录`);
  });

  // 清空
  $('btn-clear').addEventListener('click', async () => {
    if (!confirm('确定要清空全部扫描记录吗？此操作不可恢复（不影响已下载的文件）。')) return;
    await chrome.storage.local.set({ records: [] });
    await refreshDataState();
    toast('记录已清空');
  });

  // 数据变化时同步统计
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.records) refreshDataState();
  });
}

init().catch((e) => {
  toast(`初始化失败：${e.message}`);
});
