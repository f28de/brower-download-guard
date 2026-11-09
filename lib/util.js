/** 通用工具函数 */

export function fmtBytes(n) {
  if (n === null || n === undefined || Number.isNaN(n)) return '—';
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

export function fmtRelative(ts) {
  if (!ts) return '';
  const diff = Date.now() - ts;
  if (diff < 60_000) return '刚刚';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
  if (diff < 7 * 86_400_000) return `${Math.floor(diff / 86_400_000)} 天前`;
  return new Date(ts).toLocaleDateString('zh-CN');
}

export function fmtDate(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString('zh-CN', { hour12: false });
}

export function shortHash(h, head = 10, tail = 8) {
  if (!h) return '';
  if (h.length <= head + tail + 1) return h;
  return `${h.slice(0, head)}…${h.slice(-tail)}`;
}

export function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** 从下载 URL 或文件名中提取扩展名（小写，不含点） */
export function extOf(filename, url) {
  const base = (filename || '').split(/[\\/]/).pop() || '';
  const m = /\.([a-z0-9]{1,12})$/i.exec(base);
  if (m) return m[1].toLowerCase();
  try {
    const u = new URL(url);
    const m2 = /\.([a-z0-9]{1,12})$/i.exec(u.pathname);
    if (m2) return m2[1].toLowerCase();
  } catch {
    /* ignore */
  }
  return '';
}

export function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return '';
  }
}

/**
 * 清理用于展示的文件名：
 *  - 去掉 C0/C1 控制字符
 *  - 去掉零宽与双向覆写符（U+202E 等可把 "xxx.exe" 显示成 "xxx.txt"，是常见钓鱼手法）
 *  - 折叠空白、限制长度（保留扩展名）
 * 仅用于显示与存储，不参与任何文件系统路径操作。
 */
export function sanitizeName(raw) {
  let s = String(raw || '')
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, '')
    .replace(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/\s+/g, ' ')
    .trim();

  if (s === '.' || s === '..') s = '';

  if (s.length > 180) {
    const dot = s.lastIndexOf('.');
    const ext = dot > 0 && s.length - dot <= 12 ? s.slice(dot) : '';
    s = s.slice(0, 180 - ext.length) + ext;
  }
  return s || '未命名文件';
}

/** 复制到剪贴板（扩展页面内可用，失败时回退到 execCommand） */
export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      return ok;
    } catch {
      return false;
    }
  }
}

export function escapeAttr(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
