/**
 * 下载守护 —— 后台 Service Worker
 *
 * 流程：downloads.onChanged(complete) → 重新读取该文件流并计算 MD5/SHA-256
 *      → 用 SHA-256 向 VirusTotal 查询已有报告 → 更新记录 / 通知 / 角标
 *
 * 隐私：默认只把「哈希值」发给 VirusTotal，文件本体不出本机。
 */

import { createDualHasher } from './lib/hash.js';
import { getSettings, DEFAULT_SETTINGS } from './lib/settings.js';
import * as store from './lib/store.js';
import { lookupFile, uploadFile, getAnalysis, verifyKey, VtError } from './lib/vt.js';
import { fmtBytes, extOf, sleep, sanitizeName } from './lib/util.js';
import { checkUrl, isCrossOrigin } from './lib/hostpolicy.js';

const UPLOAD_LIMIT = 32 * 1024 * 1024; // VirusTotal 直传上限 32MB

class ScanError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ScanError';
    this.code = code;
  }
}

function toScanError(e) {
  if (e instanceof ScanError) return e;
  if (e instanceof VtError) return new ScanError(e.code, e.message);
  return new ScanError('unknown', e?.message || '未知错误');
}

/* ------------------------------------------------------------------ *
 * Service Worker 保活：长任务期间定时调用扩展 API，重置空闲计时器
 * ------------------------------------------------------------------ */

let activeJobs = 0;
let keepAliveTimer = null;

function acquireKeepAlive() {
  activeJobs++;
  if (keepAliveTimer === null) {
    keepAliveTimer = setInterval(() => {
      chrome.runtime.getPlatformInfo(() => void chrome.runtime.lastError);
    }, 20000);
  }
}

function releaseKeepAlive() {
  activeJobs = Math.max(0, activeJobs - 1);
  if (activeJobs === 0 && keepAliveTimer !== null) {
    clearInterval(keepAliveTimer);
    keepAliveTimer = null;
  }
}

/* ------------------------------------------------------------------ *
 * VirusTotal 请求串行化 + 限速（公共免费 Key：4 次/分钟）
 * ------------------------------------------------------------------ */

let vtTail = Promise.resolve();

/**
 * 限速状态保存在 chrome.storage.session：
 * Service Worker 被浏览器回收后重启不会丢失，避免"重启后立刻连发"打爆额度。
 * （同一时刻的并发调用由下面的 Promise 链串行化，SW 单线程即可保证不超限）
 */
const VT_STATE_KEY = 'vtState';
const VT_STATE_DEFAULT = { lastCall: 0, cooldownUntil: 0 };

async function readVtState() {
  try {
    const obj = await chrome.storage.session.get(VT_STATE_KEY);
    return { ...VT_STATE_DEFAULT, ...(obj[VT_STATE_KEY] || {}) };
  } catch {
    return { ...VT_STATE_DEFAULT };
  }
}

async function writeVtState(state) {
  try {
    await chrome.storage.session.set({ [VT_STATE_KEY]: state });
  } catch {
    /* session storage 不可用时退化为进程内限速 */
  }
}

/** 命中 429 后进入冷却期，后续请求统一延后 */
async function setVtCooldown(ms) {
  const st = await readVtState();
  await writeVtState({ ...st, cooldownUntil: Date.now() + ms });
}

function withVtSlot(task) {
  const run = async () => {
    const settings = await getSettings();
    const gap = Math.max(0, Number(settings.minIntervalMs) || 0);
    const st = await readVtState();
    const target = Math.max(st.lastCall + gap, st.cooldownUntil || 0);
    const wait = target - Date.now();
    if (wait > 0) await sleep(wait);
    await writeVtState({ lastCall: Date.now(), cooldownUntil: st.cooldownUntil || 0 });
    return task();
  };
  const p = vtTail.then(run, run);
  vtTail = p.then(
    () => undefined,
    () => undefined
  );
  return p;
}

/* ------------------------------------------------------------------ *
 * 角标
 * ------------------------------------------------------------------ */

let badgeTimer = null;

function touchBadge() {
  if (badgeTimer) clearTimeout(badgeTimer);
  badgeTimer = setTimeout(() => {
    updateBadge().catch(() => {});
  }, 150);
}

async function updateBadge() {
  let records = [];
  try {
    records = await store.list();
  } catch {
    return;
  }
  const unseen = records.filter(
    (r) => !r.seen && (r.verdict === 'malicious' || r.verdict === 'suspicious')
  ).length;
  const active = records.filter((r) =>
    ['pending', 'hashing', 'querying', 'uploading', 'analyzing'].includes(r.status)
  ).length;

  let text = '';
  let color = '#2563EB';
  if (unseen > 0) {
    text = '!';
    color = '#DC2626';
  } else if (active > 0) {
    text = '…';
    color = '#2563EB';
  }

  try {
    await chrome.action.setBadgeText({ text });
    if (text) {
      await chrome.action.setBadgeBackgroundColor({ color });
      try {
        await chrome.action.setBadgeTextColor({ color: '#FFFFFF' });
      } catch {
        /* 旧版本不支持 */
      }
    }
  } catch {
    /* ignore */
  }
}

/* ------------------------------------------------------------------ *
 * 下载事件
 * ------------------------------------------------------------------ */

const handled = new Set(); // 已处理过的 downloadId，避免重复触发
const running = new Set(); // 正在扫描的记录 id

chrome.downloads.onChanged.addListener((delta) => {
  if (!delta.state || delta.state.current !== 'complete') return;
  const id = delta.id;
  if (handled.has(id)) return;
  handled.add(id);
  if (handled.size > 500) {
    // 防止长期运行内存增长
    const first = handled.values().next().value;
    handled.delete(first);
  }
  handleDownloadComplete(id).catch((e) => console.error('[下载守护] 处理下载失败', e));
});

async function handleDownloadComplete(downloadId) {
  let item;
  try {
    const found = await chrome.downloads.search({ id: downloadId });
    item = found && found[0];
  } catch {
    return;
  }
  if (!item || item.state !== 'complete') return;
  if (item.byExtensionId && item.byExtensionId === chrome.runtime.id) return;

  const settings = await getSettings();
  if (!settings.autoScan) return;

  const filename = baseName(item);
  if (isExcluded(filename, item, settings)) return;

  const record = {
    id: crypto.randomUUID(),
    downloadId: item.id,
    filename,
    path: item.filename || '',
    url: item.url || '',
    finalUrl: item.finalUrl || item.url || '',
    mime: item.mime || '',
    fileSize: item.fileSize || 0,
    referrer: item.referrer || '',
    danger: item.danger || null,
    createdAt: Date.now(),
    status: 'pending',
    verdict: null,
    md5: null,
    sha256: null,
    stats: null,
    detections: [],
    engineTotal: 0,
    threatLabel: null,
    checkedAt: null,
    error: null,
    sizeMismatch: false,
    /** omit = 不带 Cookie（默认）；include = 用户显式授权携带登录信息 */
    credMode: 'omit',
    // 浏览器给出的 finalUrl 已是重定向后的地址，二者跨源即说明下载经过了跨域跳转
    crossOriginRedirect: !!(item.url && item.finalUrl && isCrossOrigin(item.url, item.finalUrl)),
    seen: false,
  };

  await store.upsert(record);
  await store.prune(Math.max(10, Number(settings.keepRecords) || 100));
  touchBadge();

  scan(record.id).catch((e) => console.error('[下载守护] 扫描失败', e));
}

function baseName(item) {
  const raw = item.filename || '';
  let name = raw.split(/[\\/]/).pop() || '';
  if (!name) {
    try {
      const u = new URL(item.finalUrl || item.url);
      name = decodeURIComponent(u.pathname.split('/').pop() || '');
    } catch {
      name = '';
    }
  }
  return sanitizeName(name);
}

function isExcluded(filename, item, settings) {
  const list = Array.isArray(settings.excludedExts) ? settings.excludedExts : [];
  if (list.length === 0) return false;
  const ext = extOf(filename, item.finalUrl || item.url);
  return ext !== '' && list.includes(ext);
}

/* ------------------------------------------------------------------ *
 * 扫描主流程
 * ------------------------------------------------------------------ */

async function scan(recordId, { force = false } = {}) {
  if (running.has(recordId)) return;
  running.add(recordId);
  acquireKeepAlive();
  try {
    let rec = await store.get(recordId);
    if (!rec) return;

    /* ---- 第一步：计算哈希 ---- */
    if (!rec.sha256 || force) {
      await store.patch(recordId, {
        status: 'hashing',
        error: null,
        verdict: null,
        detections: [],
        progress: { loaded: 0, total: rec.fileSize || 0 },
      });
      touchBadge();

      let lastWrite = 0;
      try {
        const result = await hashRecord(rec, (loaded, total) => {
          const now = Date.now();
          if (now - lastWrite < 400) return;
          lastWrite = now;
          store.patch(recordId, { progress: { loaded, total } }).catch(() => {});
        });
        rec = await store.patch(recordId, {
          md5: result.md5,
          sha256: result.sha256,
          sizeMismatch: result.mismatch,
          crossOriginRedirect: result.crossOriginRedirect,
          status: 'querying',
          error: null,
          progress: null,
        });
      } catch (e) {
        const err = toScanError(e);
        await store.patch(recordId, {
          status: 'hash_failed',
          error: { code: err.code, message: err.message },
          progress: null,
        });
        touchBadge();
        return;
      }
    }

    /* ---- 第二步：查询 VirusTotal ---- */
    const settings = await getSettings();
    if (!settings.apiKey) {
      await store.patch(recordId, { status: 'no_key' });
      touchBadge();
      return;
    }

    await store.patch(recordId, { status: 'querying' });
    touchBadge();

    try {
      const result = await withVtSlot(() => lookupFile(settings.apiKey, rec.sha256));
      if (!result.found) {
        await store.patch(recordId, {
          status: 'done',
          verdict: 'not_found',
          stats: null,
          detections: [],
          engineTotal: 0,
          threatLabel: null,
          checkedAt: Date.now(),
          error: null,
        });
      } else {
        const isThreat = result.verdict === 'malicious' || result.verdict === 'suspicious';
        await store.patch(recordId, {
          status: 'done',
          verdict: result.verdict,
          stats: result.stats,
          detections: result.detections,
          engineTotal: result.stats.total,
          threatLabel: result.threatLabel,
          typeDescription: result.typeDescription,
          lastAnalysisDate: result.lastAnalysisDate,
          checkedAt: Date.now(),
          error: null,
          // 新的威胁结论尚未被用户查看，重新点亮角标
          seen: isThreat ? false : true,
        });
      }
    } catch (e) {
      const err = toScanError(e);
      // 被限流时进入冷却期，避免后续任务继续撞墙
      if (err.code === 'rate_limit') await setVtCooldown(60000);
      await store.patch(recordId, {
        status: 'query_failed',
        error: { code: err.code, message: err.message },
      });
    }

    touchBadge();
    const finalRec = await store.get(recordId);
    if (finalRec) await notifyResult(finalRec);
  } finally {
    running.delete(recordId);
    releaseKeepAlive();
  }
}

/**
 * 重新读取下载源并流式计算哈希。
 * 采用流式读取，内存占用恒定，不会因为大文件而吃内存。
 */
async function hashRecord(rec, onProgress) {
  const settings = await getSettings();
  const url = rec.finalUrl || rec.url;

  // 请求前的地址准入检查：协议、内嵌凭证、内网地址、排除列表
  const policy = checkUrl(url, settings);
  if (!policy.ok) throw new ScanError(policy.code, policy.message);

  const max = Math.max(1024, Number(settings.maxHashBytes) || DEFAULT_SETTINGS.maxHashBytes);
  if (rec.fileSize && rec.fileSize > max) {
    throw new ScanError(
      'too_large',
      `文件大小 ${fmtBytes(rec.fileSize)}，超过自动哈希上限 ${fmtBytes(max)}，已跳过自动查毒`
    );
  }

  const withCreds = rec.credMode === 'include';
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), Math.max(5000, Number(settings.fetchTimeoutMs) || 120000));

  let res;
  try {
    res = await fetch(url, {
      // 默认不携带任何 Cookie（omit）。只有用户在单条记录上显式点击
      // 「携带登录信息重试」后，该记录才会以 include 模式重取一次。
      credentials: withCreds ? 'include' : 'omit',
      cache: 'no-store',
      // 携带凭证时禁止跟随重定向：Cookie 绝不能被带到跳转目标
      redirect: withCreds ? 'error' : 'follow',
      referrerPolicy: 'no-referrer',
      signal: ctrl.signal,
    });
  } catch (e) {
    clearTimeout(timer);
    if (e && e.name === 'AbortError') {
      throw new ScanError('timeout', '重新读取下载源超时，无法完成哈希计算');
    }
    if (withCreds) {
      throw new ScanError(
        'fetch_failed',
        '携带登录信息的请求未能完成：该来源可能发生了重定向（出于安全考虑，带凭证的请求不跟随跳转），或网络不可达'
      );
    }
    throw new ScanError(
      'fetch_failed',
      '无法重新读取下载源（可能需要登录、链接已失效或被服务器拒绝），可改用「携带登录信息重试」或手动送检'
    );
  }

  if (!res.ok) {
    clearTimeout(timer);
    throw new ScanError('fetch_failed', `下载源返回 HTTP ${res.status}，无法读取文件内容`);
  }
  if (!res.body) {
    clearTimeout(timer);
    throw new ScanError('fetch_failed', '当前环境不支持流式读取文件');
  }

  // 记录是否发生了跨源跳转：跳转后的内容不一定还是同一个文件，需要在界面上提示
  const finalUrl = res.url || url;
  const crossOriginRedirect =
    !!rec.crossOriginRedirect || (!!res.redirected && isCrossOrigin(finalUrl, url));

  const hasher = createDualHasher();
  const reader = res.body.getReader();
  const declared = Number(res.headers.get('content-length')) || 0;
  const total = declared || rec.fileSize || 0;
  let loaded = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      loaded += value.byteLength;
      if (loaded > max) {
        await reader.cancel().catch(() => {});
        throw new ScanError(
          'too_large',
          `文件实际大小超过自动哈希上限 ${fmtBytes(max)}，已中止`
        );
      }
      hasher.update(value);
      onProgress(loaded, total);
    }
  } finally {
    clearTimeout(timer);
  }

  if (loaded === 0) {
    throw new ScanError('empty', '读取到的文件内容为空，无法计算哈希');
  }

  const mismatch = rec.fileSize > 0 && loaded !== rec.fileSize;
  return { ...hasher.digest(), mismatch, crossOriginRedirect };
}

/* ------------------------------------------------------------------ *
 * 上传查毒（用户主动点击才会执行）
 * ------------------------------------------------------------------ */

async function uploadAndAnalyze(recordId) {
  const rec = await store.get(recordId);
  if (!rec) throw new ScanError('not_found', '记录不存在');
  const settings = await getSettings();
  if (!settings.apiKey) throw new ScanError('no_key', '请先在设置中填写 VirusTotal API Key');
  if (!rec.sha256) throw new ScanError('no_hash', '请先完成哈希计算再上传');
  if (rec.fileSize > UPLOAD_LIMIT) {
    throw new ScanError('too_large', '文件超过 32MB，VirusTotal 直传接口不支持，请到网站手动上传');
  }

  acquireKeepAlive();
  try {
    await store.patch(recordId, { status: 'uploading', error: null });
    touchBadge();

    const blob = await fetchBlob(rec, UPLOAD_LIMIT);
    const { analysisId } = await withVtSlot(() => uploadFile(settings.apiKey, blob, rec.filename));
    await store.patch(recordId, { status: 'analyzing', analysisId });
    touchBadge();

    const deadline = Date.now() + 240000;
    while (Date.now() < deadline) {
      await sleep(4000);
      const r = await withVtSlot(() => getAnalysis(settings.apiKey, analysisId));
      if (r.done) {
        await store.patch(recordId, {
          status: 'done',
          verdict: r.verdict,
          stats: r.stats,
          detections: r.detections,
          engineTotal: r.stats.total,
          threatLabel: r.threatLabel,
          typeDescription: r.typeDescription,
          checkedAt: Date.now(),
          error: null,
          uploaded: true,
        });
        const finalRec = await store.get(recordId);
        if (finalRec) await notifyResult(finalRec);
        return { analysisId };
      }
    }
    throw new ScanError('timeout', '分析耗时较长，请稍后在 VirusTotal 网站查看结果');
  } catch (e) {
    const err = toScanError(e);
    await store.patch(recordId, {
      status: 'query_failed',
      error: { code: err.code, message: err.message },
    });
    throw err;
  } finally {
    releaseKeepAlive();
    touchBadge();
  }
}

async function fetchBlob(rec, limit) {
  const url = rec.finalUrl || rec.url;
  const settings = await getSettings();
  const policy = checkUrl(url, settings);
  if (!policy.ok) throw new ScanError(policy.code, policy.message);
  const withCreds = rec.credMode === 'include';
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), Math.max(5000, Number(settings.fetchTimeoutMs) || 120000));
  try {
    const res = await fetch(url, {
      credentials: withCreds ? 'include' : 'omit',
      cache: 'no-store',
      redirect: withCreds ? 'error' : 'follow',
      referrerPolicy: 'no-referrer',
      signal: ctrl.signal,
    });
    if (!res.ok) throw new ScanError('fetch_failed', `下载源返回 HTTP ${res.status}`);
    const len = Number(res.headers.get('content-length')) || 0;
    if (len && len > limit) throw new ScanError('too_large', '文件超过上传上限');
    const buf = await res.arrayBuffer();
    if (buf.byteLength > limit) throw new ScanError('too_large', '文件超过上传上限');
    return new Blob([buf], { type: rec.mime || 'application/octet-stream' });
  } catch (e) {
    if (e instanceof ScanError) throw e;
    throw new ScanError('fetch_failed', '无法重新读取下载源，上传失败');
  } finally {
    clearTimeout(timer);
  }
}

/* ------------------------------------------------------------------ *
 * 通知
 * ------------------------------------------------------------------ */

async function notifyResult(rec) {
  const settings = await getSettings();
  if (!settings.notify) return;

  const isThreat = rec.verdict === 'malicious' || rec.verdict === 'suspicious';
  const isClean = rec.verdict === 'clean';
  if (!isThreat && !(isClean && settings.notifyOnClean)) return;

  const title = isThreat ? `检出威胁：${rec.filename}` : `未发现威胁：${rec.filename}`;
  let message;
  if (isThreat) {
    const m = rec.stats?.malicious ?? 0;
    const s = rec.stats?.suspicious ?? 0;
    message = `${m} 个引擎报毒${s ? `，${s} 个标记可疑` : ''}（共 ${rec.engineTotal || '?'} 个引擎）`;
    if (rec.threatLabel) message += `\n${rec.threatLabel}`;
  } else {
    message = `${rec.engineTotal} 个引擎均未报毒\nSHA-256 ${(rec.sha256 || '').slice(0, 16)}…`;
  }

  const nid = `scan:${rec.id}`;
  try {
    await chrome.notifications.create(nid, {
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icons/icon128.png'),
      title,
      message,
      priority: isThreat ? 2 : 0,
      requireInteraction: false,
    });
  } catch (e) {
    console.warn('[下载守护] 通知创建失败', e);
  }

  if (isThreat && settings.autoOpenOnThreat && rec.sha256) {
    chrome.tabs
      .create({ url: `https://www.virustotal.com/gui/file/${rec.sha256}` })
      .catch(() => {});
  }
}

chrome.notifications.onClicked.addListener((nid) => {
  if (!nid.startsWith('scan:')) return;
  const id = nid.slice('scan:'.length);
  chrome.tabs
    .create({ url: chrome.runtime.getURL(`popup.html?focus=${encodeURIComponent(id)}`) })
    .catch(() => {});
  chrome.notifications.clear(nid);
});

/* ------------------------------------------------------------------ *
 * 消息接口（popup / options 调用）
 * ------------------------------------------------------------------ */

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  handleMessage(msg)
    .then((r) => sendResponse({ ok: true, ...(r || {}) }))
    .catch((e) => sendResponse({ ok: false, error: e?.message || String(e), code: e?.code || null }));
  return true; // 保持消息通道异步
});

async function handleMessage(msg) {
  if (!msg || typeof msg.type !== 'string') throw new Error('无效的请求');

  switch (msg.type) {
    case 'ping':
      return { activeJobs };

    case 'rescan': {
      if (!msg.id) throw new Error('缺少记录 id');
      const rec = await store.get(msg.id);
      if (!rec) throw new Error('记录不存在');

      if (msg.credentials === true) {
        // 提权前护栏：地址策略必须仍然通过（内网/排除列表等）
        const policy = checkUrl(rec.finalUrl || rec.url, await getSettings());
        if (!policy.ok) throw new Error(policy.message);
        await store.patch(msg.id, { credMode: 'include' });
      } else if (msg.credentials === false) {
        await store.patch(msg.id, { credMode: 'omit' });
      }

      scan(msg.id, { force: msg.force !== false }).catch(() => {});
      return {};
    }

    case 'rescanAll': {
      const records = await store.list();
      for (const r of records.slice(0, 20)) {
        scan(r.id, { force: true }).catch(() => {});
      }
      return {};
    }

    case 'delete': {
      await store.remove(msg.id);
      touchBadge();
      return {};
    }

    case 'clear': {
      await store.clear();
      touchBadge();
      return {};
    }

    case 'markSeen': {
      await store.markAllSeen();
      touchBadge();
      return {};
    }

    case 'upload': {
      // 先做同步校验，再异步启动（分析可能耗时数分钟，不阻塞消息通道）
      if (!msg.id) throw new Error('缺少记录 id');
      const rec = await store.get(msg.id);
      if (!rec) throw new Error('记录不存在');
      const s = await getSettings();
      if (!s.apiKey) throw new Error('请先在设置中填写 VirusTotal API Key');
      if (!rec.sha256) throw new Error('请先完成哈希计算');
      if ((rec.fileSize || 0) > UPLOAD_LIMIT) {
        throw new Error('文件超过 32MB，VirusTotal 直传接口不支持，请到网站手动上传');
      }
      uploadAndAnalyze(msg.id).catch((e) => console.error('[下载守护] 上传分析失败', e));
      return { started: true };
    }

    case 'verifyKey': {
      const key = String(msg.apiKey || '').trim();
      if (!key) return { ok: false, message: '请先填写 API Key' };
      return verifyKey(key);
    }

    case 'openOptions': {
      chrome.runtime.openOptionsPage();
      return {};
    }

    default:
      throw new Error(`未知请求类型：${msg.type}`);
  }
}

/* ------------------------------------------------------------------ *
 * 生命周期
 * ------------------------------------------------------------------ */

chrome.runtime.onInstalled.addListener(async (details) => {
  const settings = await getSettings();
  await chrome.storage.local.set({ settings });
  await updateBadge();
  if (details.reason === 'install') {
    chrome.runtime.openOptionsPage();
  }
});

chrome.runtime.onStartup.addListener(() => {
  updateBadge().catch(() => {});
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if (changes.settings) {
    const next = { ...DEFAULT_SETTINGS, ...(changes.settings.newValue || {}) };
    store.prune(Math.max(10, Number(next.keepRecords) || 100)).catch(() => {});
  }
  if (changes.records) touchBadge();
});
