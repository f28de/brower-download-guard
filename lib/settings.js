/** 设置项的默认值与读写 */

const KEY = 'settings';

export const DEFAULT_SETTINGS = {
  /** VirusTotal API Key，留空则只做本地哈希计算 */
  apiKey: '',
  /** 下载完成后自动查毒 */
  autoScan: true,
  /** 参与哈希计算的文件大小上限（字节），超过则跳过自动扫描 */
  maxHashBytes: 268435456, // 256 MB
  /** 两次 VirusTotal 请求之间的最小间隔（毫秒）。公共免费 Key 限制为 4 次/分钟 */
  minIntervalMs: 15000,
  /** 单次拉取文件的超时（毫秒） */
  fetchTimeoutMs: 120000,
  /**
   * 是否允许访问内网/本机地址。
   * 默认 false：避免扩展被当作内网探测跳板（SSRF）。
   * 需要扫描 NAS、内网下载站的用户可显式开启。
   */
  allowPrivateHosts: false,
  /** 永不访问的主机名（含其子域），例如内网办公系统域名 */
  hostBlocklist: [],
  /** 桌面通知 */
  notify: true,
  /** 安全文件也发通知 */
  notifyOnClean: false,
  /** 发现威胁时自动打开 VirusTotal 页面 */
  autoOpenOnThreat: false,
  /** 不扫描的扩展名（小写，不含点） */
  excludedExts: [],
  /** 最多保留的记录条数 */
  keepRecords: 100,
};

export async function getSettings() {
  const obj = await chrome.storage.local.get(KEY);
  const saved = obj[KEY] || {};
  return { ...DEFAULT_SETTINGS, ...saved };
}

export async function saveSettings(patch) {
  const current = await getSettings();
  const next = { ...current, ...patch };
  await chrome.storage.local.set({ [KEY]: next });
  return next;
}

export function onSettingsChanged(cb) {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local' || !changes[KEY]) return;
    cb({ ...DEFAULT_SETTINGS, ...(changes[KEY].newValue || {}) });
  });
}
