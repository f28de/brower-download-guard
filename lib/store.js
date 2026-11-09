/**
 * 扫描记录的持久化。
 * 所有写操作串行化（内存锁），避免多个并发任务 patch 同一条记录时互相覆盖。
 */

const KEY = 'records';
const HARD_CAP = 200;

let chain = Promise.resolve();

function lock(fn) {
  const run = chain.then(fn, fn);
  chain = run.then(
    () => undefined,
    () => undefined
  );
  return run;
}

async function readAll() {
  const obj = await chrome.storage.local.get(KEY);
  const list = obj[KEY];
  return Array.isArray(list) ? list : [];
}

async function writeAll(list) {
  const trimmed = list.slice(0, HARD_CAP);
  await chrome.storage.local.set({ [KEY]: trimmed });
  return trimmed;
}

export function list() {
  return readAll();
}

export function get(id) {
  return readAll().then((l) => l.find((r) => r.id === id) || null);
}

export function upsert(record) {
  return lock(async () => {
    const l = await readAll();
    const i = l.findIndex((r) => r.id === record.id);
    if (i >= 0) l[i] = { ...l[i], ...record };
    else l.unshift(record);
    l.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    await writeAll(l);
    return record;
  });
}

export function patch(id, changes) {
  return lock(async () => {
    const l = await readAll();
    const i = l.findIndex((r) => r.id === id);
    if (i < 0) return null;
    l[i] = { ...l[i], ...changes };
    await writeAll(l);
    return l[i];
  });
}

export function remove(id) {
  return lock(async () => {
    const l = await readAll();
    await writeAll(l.filter((r) => r.id !== id));
  });
}

export function clear() {
  return lock(() => writeAll([]));
}

export function markAllSeen() {
  return lock(async () => {
    const l = await readAll();
    let changed = false;
    for (const r of l) {
      if (!r.seen) {
        r.seen = true;
        changed = true;
      }
    }
    if (changed) await writeAll(l);
    return changed;
  });
}

/** 按设置裁剪历史记录条数 */
export function prune(keep) {
  return lock(async () => {
    const l = await readAll();
    if (l.length > keep) await writeAll(l.slice(0, keep));
  });
}
