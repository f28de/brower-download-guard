/**
 * VirusTotal API v3 客户端
 * 文档：https://docs.virustotal.com/reference/overview
 *
 * 说明：
 *  - 查毒默认走「哈希查询」接口（GET /files/{hash}），只上传哈希值，不上传文件内容，隐私友好。
 *  - 仅当用户在界面上明确点击「上传查毒」时，才会把文件本体上传到 VirusTotal。
 *  - 免费版 API Key 的额度为：4 次/分钟、500 次/天、15.5K 次/月。商业用途需向 VirusTotal 申请商业授权。
 *  - API Key 只保存在本机 chrome.storage.local，仅随请求发送给 www.virustotal.com，不上报给任何第三方。
 */

const BASE = 'https://www.virustotal.com/api/v3';

export class VtError extends Error {
  constructor(code, message, status) {
    super(message);
    this.name = 'VtError';
    this.code = code;
    this.status = status ?? null;
  }
}

async function describe(res) {
  try {
    const j = await res.json();
    const raw = j?.error?.message || j?.error?.code || '';
    // 只保留简短摘要，避免把上游的长文本原样透传到界面
    const text = String(raw).replace(/\s+/g, ' ').trim();
    return text.length > 120 ? text.slice(0, 120) + '…' : text;
  } catch {
    return '';
  }
}

function netError() {
  return new VtError('network', '网络请求失败，请检查网络连接或代理设置');
}

function statusError(status, detail) {
  const suffix = detail ? `：${detail}` : '';
  switch (status) {
    case 401:
      return new VtError('invalid_key', 'API Key 无效或已被撤销，请在设置中重新填写', status);
    case 403:
      return new VtError('forbidden', '当前 API Key 无权访问该接口（免费版 Key 有功能限制）', status);
    case 429:
      return new VtError('rate_limit', '已触发 VirusTotal 免费额度限制（4 次/分钟、500 次/天），请稍后再试', status);
    case 404:
      return new VtError('not_found', 'VirusTotal 未收录该文件', status);
    default:
      return new VtError(`http_${status}`, `VirusTotal 返回 HTTP ${status}${suffix}`, status);
  }
}

/* ------------------------------------------------------------------ *
 * 结果归一化
 * ------------------------------------------------------------------ */

function normalizeStats(attrs) {
  // files 接口用 last_analysis_stats，analyses 接口用 stats
  const s = attrs.last_analysis_stats || attrs.stats || {};
  const num = (v) => (typeof v === 'number' ? v : 0);
  const malicious = num(s.malicious);
  const suspicious = num(s.suspicious);
  const harmless = num(s.harmless);
  const undetected = num(s.undetected);
  const timeout = num(s.timeout);
  const failure = num(s.failure);
  return {
    malicious,
    suspicious,
    harmless,
    undetected,
    timeout,
    failure,
    total: malicious + suspicious + harmless + undetected + timeout + failure,
  };
}

/**
 * 把 VirusTotal 的 attributes 转成本插件使用的结构。
 * 传入的 results 可以是 last_analysis_results（文件查询）或 analysis.results（上传分析）。
 */
export function summarize(attrs, results) {
  const stats = normalizeStats(attrs);
  const table = results || attrs.last_analysis_results || {};

  const detections = Object.values(table)
    .filter((r) => r && (r.category === 'malicious' || r.category === 'suspicious'))
    .map((r) => ({
      engine: r.engine_name || r.engine || 'unknown',
      name: r.result || '—',
      category: r.category,
    }))
    .sort((a, b) => (a.engine > b.engine ? 1 : -1))
    .slice(0, 20);

  let verdict = 'unknown';
  if (stats.malicious > 0) verdict = 'malicious';
  else if (stats.suspicious > 0) verdict = 'suspicious';
  else if (stats.total > 0) verdict = 'clean';

  const ptc = attrs.popular_threat_classification || {};
  const threatLabel =
    ptc.suggested_threat_label ||
    ptc.popular_threat_name?.[0]?.value ||
    null;

  return {
    verdict,
    stats,
    detections,
    threatLabel,
    typeDescription: attrs.type_description || null,
    names: Array.isArray(attrs.names) ? attrs.names.slice(0, 6) : [],
    reputation: typeof attrs.reputation === 'number' ? attrs.reputation : null,
    tags: Array.isArray(attrs.tags) ? attrs.tags.slice(0, 8) : [],
    lastAnalysisDate: attrs.last_analysis_date ? attrs.last_analysis_date * 1000 : null,
    firstSubmissionDate: attrs.first_submission_date ? attrs.first_submission_date * 1000 : null,
  };
}

/* ------------------------------------------------------------------ *
 * 哈希查询
 * ------------------------------------------------------------------ */

/**
 * @param {string} apiKey
 * @param {string} hash md5 / sha1 / sha256 均可
 * @returns {Promise<{found: boolean} & ReturnType<typeof summarize>>}
 */
export async function lookupFile(apiKey, hash) {
  let res;
  try {
    res = await fetch(`${BASE}/files/${encodeURIComponent(hash)}`, {
      headers: { 'x-apikey': apiKey },
      cache: 'no-store',
    });
  } catch {
    throw netError();
  }

  if (res.status === 404) return { found: false };
  if (!res.ok) throw statusError(res.status, await describe(res));

  let json;
  try {
    json = await res.json();
  } catch {
    throw new VtError('bad_response', 'VirusTotal 返回数据解析失败');
  }

  const attrs = json?.data?.attributes;
  if (!attrs) throw new VtError('bad_response', 'VirusTotal 返回数据结构异常');
  return { found: true, ...summarize(attrs) };
}

/* ------------------------------------------------------------------ *
 * 文件上传分析（仅在用户明确点击时调用）
 * ------------------------------------------------------------------ */

/**
 * 上传文件到 VirusTotal 进行分析。
 * @param {string} apiKey
 * @param {Blob} blob
 * @param {string} filename
 * @returns {Promise<{analysisId: string}>}
 */
export async function uploadFile(apiKey, blob, filename) {
  const form = new FormData();
  form.append('file', blob, filename || 'download.bin');

  let res;
  try {
    res = await fetch(`${BASE}/files`, {
      method: 'POST',
      headers: { 'x-apikey': apiKey },
      body: form,
    });
  } catch {
    throw netError();
  }

  if (!res.ok) {
    const detail = await describe(res);
    if (res.status === 409) throw new VtError('already_exists', 'VirusTotal 已存在该文件，请重新扫描查询结果', 409);
    if (res.status === 413) throw new VtError('too_large', '文件超过 VirusTotal 直传上限（32MB），请到网站手动上传', 413);
    throw statusError(res.status, detail);
  }

  let json;
  try {
    json = await res.json();
  } catch {
    throw new VtError('bad_response', 'VirusTotal 返回数据解析失败');
  }
  const id = json?.data?.id;
  if (!id) throw new VtError('bad_response', 'VirusTotal 未返回分析 ID');
  return { analysisId: id };
}

/**
 * 查询一次分析任务的状态。
 * @returns {Promise<{status: string, done: boolean} & Partial<ReturnType<typeof summarize>>>}
 */
export async function getAnalysis(apiKey, analysisId) {
  let res;
  try {
    res = await fetch(`${BASE}/analyses/${encodeURIComponent(analysisId)}`, {
      headers: { 'x-apikey': apiKey },
      cache: 'no-store',
    });
  } catch {
    throw netError();
  }
  if (!res.ok) throw statusError(res.status, await describe(res));

  const json = await res.json();
  const attrs = json?.data?.attributes;
  if (!attrs) throw new VtError('bad_response', 'VirusTotal 返回数据结构异常');

  const status = attrs.status || 'unknown';
  if (status !== 'completed') {
    return { status, done: false };
  }
  return { status, done: true, ...summarize(attrs, attrs.results) };
}

/** 校验 Key 是否可用：用空文件哈希查询，404 也算 Key 有效 */
export async function verifyKey(apiKey) {
  const emptySha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  try {
    await lookupFile(apiKey, emptySha256);
    return { ok: true, message: 'API Key 可用' };
  } catch (e) {
    if (e instanceof VtError && e.code === 'not_found') {
      return { ok: true, message: 'API Key 可用' };
    }
    return { ok: false, message: e?.message || '校验失败' };
  }
}
