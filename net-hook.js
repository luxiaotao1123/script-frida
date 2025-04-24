/* ========== 0. 环境检查 ========== */
if (!ObjC.available) { console.log('⚠️ ObjC 不可用'); }

/* ========== 1. 小工具 ========== */
function S(o) { try { return (!o || o.isNull()) ? '' : o.toString(); } catch (_) { return ''; } }
function D(dict) {
    const out = {}; if (!dict || dict.isNull()) return out;
    try {
        const ks = dict.allKeys(); for (let i = 0; i < ks.count(); i++) {
            const k = ks.objectAtIndex_(i), v = dict.objectForKey_(k);
            const kk = S(k), vv = S(v); if (kk) out[kk] = vv;
        }
    } catch (_) { }
    return out;
}

/* ========== 2. 全局映射 & 去重集 ========== */
let next = 1;
const t2id = new Map(), b2id = new Map(), skipT = new Set();
const bodyDone = new Set(), finishDone = new Set();

/* ========== 3. -resume 打印请求（仅 textnow） ========== */
Interceptor.attach(
    ObjC.classes.NSURLSessionTask['- resume'].implementation, {
    onEnter(a) {
        try {
            const task = new ObjC.Object(a[0]),
                req = task.currentRequest() || task.originalRequest();
            if (!req || req.isNull()) return;

            const url = S(req.URL() && req.URL().absoluteString());
            if (url.indexOf('textnow.me') === -1) {         // ← 只关心 textnow
                skipT.add(task.handle.toString());
                return;
            }
            /* --- 记录 & 打印 --- */
            const id = (t2id.get(task.handle.toString()) || (t2id.set(task.handle.toString(), next), next++));
            console.log(`[${id}] → ${S(req.HTTPMethod()) || 'GET'} ${url}`);

            const hdr = D(req.allHTTPHeaderFields());
            if (Object.keys(hdr).length) console.log('    • 头部:', JSON.stringify(hdr));

            const body = req.HTTPBody();
            if (body && !body.isNull()) {
                const bs = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4);
                console.log('    • 请求体:', S(bs));
            }
        } catch (e) { console.log('[! 请求打印]', e); }
    }
});

/* ========== 4. completion-handler 回调（保留，去重） ========== */
function hookC(sel) {
    const C = ObjC.classes.NSURLSession; if (!(sel in C)) return;
    const seen = new Set();
    Interceptor.attach(C[sel].implementation, {
        onEnter(a) { this.b = a[3]; },
        onLeave(ret) {
            const blk = this.b; if (!blk || blk.isNull()) return;
            const key = blk.toString();
            /* 过滤被 skip 的任务 */
            const idMap = (obj) => {
                const k = obj.handle.toString(); if (skipT.has(k)) return null;
                if (!t2id.has(k)) t2id.set(k, next++);
                return t2id.get(k);
            };
            const id = idMap(new ObjC.Object(ret)); if (id === null) return;
            b2id.set(key, id);

            const inv = Memory.readPointer(blk.add(Process.pointerSize * 2));
            if (inv.isNull() || seen.has(inv.toString())) return; seen.add(inv.toString());

            Interceptor.attach(inv, {
                onEnter(c) {
                    const id = b2id.get(key); if (id === undefined) return;
                    try {
                        const d = c[1], r = c[2], e = c[3];
                        /* -- finish & header 去重 -- */
                        if (r && !r.isNull() && !finishDone.has(id)) {
                            finishDone.add(id);
                            const R = new ObjC.Object(r);
                            console.log(`[${id}] ← ${R.statusCode && R.statusCode()} ${S(R.URL && R.URL().absoluteString())}`);
                            const h = D(R.allHeaderFields && R.allHeaderFields());
                            if (Object.keys(h).length) console.log('    • 头部:', JSON.stringify(h));
                        }
                        /* -- body 去重 -- */
                        if (d && !d.isNull() && !bodyDone.has(id)) {
                            bodyDone.add(id);
                            let s = ObjC.classes.NSString.alloc().initWithData_encoding_(new ObjC.Object(d), 4);
                            const MAX = 500; if (s && s.length() > MAX) s = s.substr(0, MAX) + ' …(truncated)';
                            if (s && s.length() > 0) console.log('    • 响应体:', S(s));
                        }
                        if (e && !e.isNull()) {
                            const E = new ObjC.Object(e);
                            console.log('    • 错误:', S(E.localizedDescription && E.localizedDescription()));
                        }
                    } catch (x) { console.log('[! block 回调]', x); }
                }
            });
        }
    });
}
hookC('- dataTaskWithRequest:completionHandler:');
hookC('- dataTaskWithURL:completionHandler:');

/* ========== 5. delegate-style 回调（轻量，去重） ========== */
const msgSend = Module.getExportByName(null, 'objc_msgSend');
const SEL_DATA = ObjC.selector('URLSession:dataTask:didReceiveData:');
const SEL_FINISH = ObjC.selector('URLSession:task:didCompleteWithError:');

Interceptor.attach(msgSend, {
    onEnter(a) {
        const cmd = a[1];
        if (cmd.equals(SEL_DATA)) {
            const taskPtr = a[3], dataPtr = a[4];
            const k = taskPtr.toString(); if (skipT.has(k) || !t2id.has(k)) return;
            const id = t2id.get(k); if (bodyDone.has(id) || !dataPtr || dataPtr.isNull()) return;
            bodyDone.add(id);
            let s = ObjC.classes.NSString.alloc().initWithData_encoding_(new ObjC.Object(dataPtr), 4);
            const MAX = 500; if (s && s.length() > MAX) s = s.substr(0, MAX) + ' …(truncated)';
            if (s && s.length() > 0) console.log(`[${id}] ← (chunk)    • 响应体:`, S(s));
        }
        else if (cmd.equals(SEL_FINISH)) {
            const taskPtr = a[3], errPtr = a[4];
            const k = taskPtr.toString(); if (skipT.has(k) || !t2id.has(k)) return;
            const id = t2id.get(k); if (finishDone.has(id)) return;
            finishDone.add(id);
            try {
                const task = new ObjC.Object(taskPtr), resp = task.response && task.response();
                if (resp && !resp.isNull()) {
                    console.log(`[${id}] ← ${resp.statusCode && resp.statusCode()} ${S(resp.URL && resp.URL().absoluteString())}`);
                    const h = D(resp.allHeaderFields && resp.allHeaderFields());
                    if (Object.keys(h).length) console.log('    • 头部:', JSON.stringify(h));
                }
                if (errPtr && !errPtr.isNull()) {
                    const E = new ObjC.Object(errPtr);
                    console.log('    • 错误:', S(E.localizedDescription && E.localizedDescription()));
                }
            } catch (e) { console.log('[! delegate finish]', e); }
        }
    }
});

console.log('✅ 仅 textnow & 去重 完成注入');