/**
 * 网页端查毒站点清单。
 *
 * hashLookup = true  站点支持直接用哈希打开报告页
 * hashLookup = false 站点只能手动上传文件，点击时会先把哈希复制到剪贴板
 */

export const SITES = [
  {
    id: 'virustotal',
    name: 'VirusTotal',
    desc: '70+ 引擎聚合',
    hashLookup: true,
    build: (h) => `https://www.virustotal.com/gui/file/${h}`,
  },
  {
    id: 'kaspersky',
    name: 'Kaspersky OpenTIP',
    desc: '卡巴斯基威胁情报',
    hashLookup: true,
    build: (h) => `https://opentip.kaspersky.com/${h}/results?tab=lookup`,
  },
  {
    id: 'hybrid',
    name: 'Hybrid Analysis',
    desc: '混合动态分析',
    hashLookup: true,
    build: (h) => `https://www.hybrid-analysis.com/search?query=${h}`,
  },
  {
    id: 'virscan',
    name: 'VirScan',
    desc: '多引擎在线检测',
    hashLookup: false,
    build: () => 'https://www.virscan.org/',
  },
  {
    id: 'jotti',
    name: 'Jotti',
    desc: '多引擎扫描',
    hashLookup: false,
    build: () => 'https://virusscan.jotti.org/',
  },
];

export function getSite(id) {
  return SITES.find((s) => s.id === id) || null;
}

/** 生成站点链接；sha256 缺失时返回 null */
export function siteUrl(siteId, sha256) {
  const site = getSite(siteId);
  if (!site || !sha256) return null;
  return site.build(sha256);
}
