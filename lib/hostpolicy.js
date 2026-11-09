/**
 * 下载地址安全策略
 *
 * 目的：限制扩展"主动发起请求"的范围。扩展能带着 host 权限跨域取数，
 * 这是网页做不到的，所以必须在发出请求前做地址判定，避免被当成
 * 内网探测 / SSRF 跳板。
 *
 * 判定为"内网/本机"的地址默认拒绝，用户可在设置中显式放行（NAS、内网下载站等）。
 */

/** 判断主机名是否属于本机 / 内网 / 链路本地 / 保留地址 */
export function isPrivateHost(hostname) {
  const host = String(hostname || '')
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');

  if (!host) return true;
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host === 'localhost.localdomain') return true;
  if (host === '0.0.0.0' || host === '::') return true;
  if (host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.home.arpa')) return true;

  /* IPv4 */
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (m) {
    const parts = m.slice(1).map(Number);
    if (parts.some((n) => n > 255)) return true; // 非法写法，按不可信处理
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true; // 本网络 / 私有 / 环回
    if (a === 169 && b === 254) return true; // 链路本地（云元数据 169.254.169.254）
    if (a === 172 && b >= 16 && b <= 31) return true; // 私有
    if (a === 192 && b === 168) return true; // 私有
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a === 198 && (b === 18 || b === 19)) return true; // 基准测试网段
    if (a >= 224) return true; // 组播 / 保留
    return false;
  }

  /* IPv6 */
  if (host.includes(':')) {
    if (host === '::1') return true;
    if (/^f[cd][0-9a-f]{2}:/.test(host)) return true; // fc00::/7 唯一本地地址
    if (/^fe[89ab][0-9a-f]:/.test(host)) return true; // fe80::/10 链路本地
    if (/^::ffff:/.test(host)) return isPrivateHost(host.slice(7)); // IPv4 映射
    return false;
  }

  /* 单标签主机名（如 http://nas/file）通常是内网主机 */
  if (!host.includes('.')) return true;

  return false;
}

/**
 * 请求前的地址准入检查。
 * @param {string} rawUrl
 * @param {{allowPrivateHosts?: boolean, hostBlocklist?: string[]}} settings
 * @returns {{ok: true} | {ok: false, code: string, message: string}}
 */
export function checkUrl(rawUrl, settings = {}) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return { ok: false, code: 'unsupported_url', message: '下载地址无法解析，无法读取文件内容' };
  }

  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return {
      ok: false,
      code: 'unsupported_url',
      message: `不支持 ${u.protocol} 协议（可能是 blob: 或本地生成的文件），无法读取内容计算哈希`,
    };
  }

  if (u.username || u.password) {
    return {
      ok: false,
      code: 'unsafe_url',
      message: '下载地址中内嵌了账号密码，出于安全考虑已跳过自动读取',
    };
  }

  const host = u.hostname.toLowerCase();

  const blocklist = Array.isArray(settings.hostBlocklist) ? settings.hostBlocklist : [];
  if (blocklist.some((h) => h && (host === h || host.endsWith('.' + h)))) {
    return { ok: false, code: 'blocked_host', message: `主机 ${host} 在排除列表中，已跳过自动读取` };
  }

  if (!settings.allowPrivateHosts && isPrivateHost(host)) {
    return {
      ok: false,
      code: 'private_host',
      message: '该地址属于本机或内网，默认不主动访问。如需扫描内网下载源，可在设置中开启「允许扫描内网地址」',
    };
  }

  return { ok: true };
}

/** 两个 URL 是否跨源（协议 / 主机 / 端口任一不同即为跨源） */
export function isCrossOrigin(a, b) {
  try {
    return new URL(a).origin !== new URL(b).origin;
  } catch {
    return true;
  }
}
