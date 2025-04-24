/* ========== 0. 环境检查 ========== */
if (!ObjC.available) { console.log('⚠️ ObjC 不可用'); }

/* ========== 1. 工具 ========== */
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

/* ========== 2. 全局映射 ========== */
let next = 1;
const t2id = new Map(), b2id = new Map();
function id(t) { const k = t.handle.toString(); let v = t2id.get(k); if (!v) { v = next++; t2id.set(k, v); } return v; }

/* ========== 3. -resume 打印请求 ========== */
Interceptor.attach(
    ObjC.classes.NSURLSessionTask['- resume'].implementation, {
    onEnter(a) {
        try {
            const task = new ObjC.Object(a[0]), n = id(task),
                req = task.currentRequest() || task.originalRequest();
            if (!req || req.isNull()) return;

            console.log(`[${n}] → ${S(req.HTTPMethod()) || 'GET'} ${S(req.URL() && req.URL().absoluteString())}`);
            const h = D(req.allHTTPHeaderFields()); if (Object.keys(h).length) console.log('    • 头部:', JSON.stringify(h));

            const body = req.HTTPBody(); if (body && !body.isNull()) {
                const bs = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4);
                console.log('    • 请求体:', S(bs));
            }
        } catch (e) { console.log('[! 请求打印]', e); }
    }
});

/* ========== 4. completion-handler 回调 ========== */
function hookC(sel) {
    const C = ObjC.classes.NSURLSession; if (!(sel in C)) return;
    const seen = new Set();
    Interceptor.attach(C[sel].implementation, {
        onEnter(a) { this.b = a[3]; },
        onLeave(ret) {
            const blk = this.b; if (!blk || blk.isNull()) return;
            const n = id(new ObjC.Object(ret)); b2id.set(blk.toString(), n);
            const inv = Memory.readPointer(blk.add(Process.pointerSize * 2));
            if (inv.isNull() || seen.has(inv.toString())) return; seen.add(inv.toString());

            Interceptor.attach(inv, {
                onEnter(c) {
                    const n = b2id.get(blk.toString()); if (!n) return;
                    try {
                        const d = c[1], r = c[2], e = c[3];
                        if (r && !r.isNull()) {
                            const R = new ObjC.Object(r);
                            console.log(`[${n}] ← ${R.statusCode && R.statusCode()} ${S(R.URL && R.URL().absoluteString())}`);
                            const h = D(R.allHeaderFields && R.allHeaderFields());
                            if (Object.keys(h).length) console.log('    • 头部:', JSON.stringify(h));
                        }
                        if (d && !d.isNull()) {
                            const s = ObjC.classes.NSString.alloc().initWithData_encoding_(new ObjC.Object(d), 4);
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

/* ========== 5. 极简 objc_msgSend 过滤器 ========== */
const msgSend = Module.getExportByName(null, 'objc_msgSend');
const SEL_DATA = ObjC.selector('URLSession:dataTask:didReceiveData:');
const SEL_FINISH = ObjC.selector('URLSession:task:didCompleteWithError:');

Interceptor.attach(msgSend, {
    onEnter(a) {
        const cmdPtr = a[1];
        if (cmdPtr.equals(SEL_DATA)) {
            const taskPtr = a[3], dataPtr = a[4], n = t2id.get(taskPtr.toString());
            if (!n || !dataPtr || dataPtr.isNull()) return;
            const body = ObjC.classes.NSString.alloc().initWithData_encoding_(new ObjC.Object(dataPtr), 4);
            if (body && body.length() > 0) console.log(`[${n}] ← (chunk)    • 响应体:`, S(body));
        }
        else if (cmdPtr.equals(SEL_FINISH)) {
            const taskPtr = a[3], errPtr = a[4], n = t2id.get(taskPtr.toString()); if (!n) return;
            try {
                const task = new ObjC.Object(taskPtr), resp = task.response && task.response();
                if (resp && !resp.isNull()) {
                    console.log(`[${n}] ← ${resp.statusCode && resp.statusCode()} ${S(resp.URL && resp.URL().absoluteString())}`);
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

console.log('✅ 兼容 delegate + completion，且性能可用');