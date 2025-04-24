// 先卸载之前所有拦截器，避免日志重复
Interceptor.detachAll();
// 配置拦截域名，只需修改此变量即可
const FILTER_DOMAIN = 'textnow.me';
if (FILTER_DOMAIN) {
    console.log('🛡️  当前拦截域名：' + FILTER_DOMAIN);
}


if (!ObjC.available) { console.log('⚠️ ObjC 不可用'); }

function S(o) { try { return (!o || o.isNull()) ? '' : o.toString(); } catch (_) { return ''; } }
function D(dict) {
    const out = {};
    if (!dict || dict.isNull()) return out;
    try {
        const keys = dict.allKeys();
        for (let i = 0; i < keys.count(); i++) {
            const k = keys.objectAtIndex_(i), v = dict.objectForKey_(k);
            const kk = S(k), vv = S(v);
            if (kk) out[kk] = vv;
        }
    } catch (_) { }
    return out;
}

let next = 1;
const t2id = new Map(), b2id = new Map();
function id(obj) {
    const key = obj.handle.toString();
    if (!t2id.has(key)) t2id.set(key, next++);
    return t2id.get(key);
}

// 拦截 NSURLSessionTask resume
Interceptor.attach(ObjC.classes.NSURLSessionTask['- resume'].implementation, {
    onEnter(args) {
        try {
            const task = new ObjC.Object(args[0]);
            const req = task.currentRequest() || task.originalRequest();
            if (!req || req.isNull()) return;
            const url = S(req.URL().absoluteString());
            if (!url.includes(FILTER_DOMAIN)) return;
            const n = id(task);
            console.log(`[${n}] → ${S(req.HTTPMethod()) || 'GET'} ${url}`);
            const headers = D(req.allHTTPHeaderFields());
            if (Object.keys(headers).length) console.log('    • 头部:', JSON.stringify(headers));
            const body = req.HTTPBody();
            if (body && !body.isNull()) {
                const text = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4);
                console.log('    • 请求体:', S(text));
            }
        } catch (e) { console.log('[! resume]', e); }
    }
});

function hookCompletion(selector) {
    const C = ObjC.classes.NSURLSession;
    if (!(selector in C)) return;
    const seen = new Set();
    Interceptor.attach(C[selector].implementation, {
        onEnter(args) { this.block = args[3]; },
        onLeave(ret) {
            const blk = this.block;
            if (!blk || blk.isNull()) return;
            const inv = Memory.readPointer(blk.add(Process.pointerSize * 2));
            if (inv.isNull() || seen.has(inv.toString())) return;
            seen.add(inv.toString());
            const idn = id(new ObjC.Object(ret));
            b2id.set(blk.toString(), idn);
            Interceptor.attach(inv, {
                onEnter(args) {
                    const idx = b2id.get(blk.toString());
                    if (!idx) return;
                    try {
                        const data = args[1], resp = args[2], err = args[3];
                        if (resp && !resp.isNull()) {
                            const R = new ObjC.Object(resp);
                            const url = S(R.URL().absoluteString());
                            if (!url.includes(FILTER_DOMAIN)) return;
                            console.log(`[${idx}] ← ${R.statusCode()} ${url}`);
                            const h = D(R.allHeaderFields());
                            if (Object.keys(h).length) console.log('    • 头部:', JSON.stringify(h));
                        }
                        if (data && !data.isNull()) {
                            const str = ObjC.classes.NSString.alloc().initWithData_encoding_(new ObjC.Object(data), 4);
                            if (str.length()) console.log('    • 响应体:', S(str));
                        }
                        if (err && !err.isNull()) {
                            const E = new ObjC.Object(err);
                            console.log('    • 错误:', S(E.localizedDescription));
                        }
                    } catch (e) { console.log('[! block]', e); }
                }
            });
        }
    });
}
hookCompletion('- dataTaskWithRequest:completionHandler:');
hookCompletion('- dataTaskWithURL:completionHandler:');

// Delegate 方式
const msgSend = Module.getExportByName(null, 'objc_msgSend');
const SEL_DATA = ObjC.selector('URLSession:dataTask:didReceiveData:');
const SEL_FINISH = ObjC.selector('URLSession:task:didCompleteWithError:');

Interceptor.attach(msgSend, {
    onEnter(args) {
        const sel = args[1];
        if (sel.equals(SEL_DATA)) {
            const taskPtr = args[3], dataPtr = args[4];
            const idn = t2id.get(taskPtr.toString());
            if (!idn || !dataPtr || dataPtr.isNull()) return;
            const task = new ObjC.Object(taskPtr);
            const url = S(task.currentRequest().URL.absoluteString());
            if (!url.includes(FILTER_DOMAIN)) return;
            const chunk = ObjC.classes.NSString.alloc().initWithData_encoding_(new ObjC.Object(dataPtr), 4);
            if (chunk.length()) console.log(`[${idn}] ← (chunk)    • 响应体:`, S(chunk));
        } else if (sel.equals(SEL_FINISH)) {
            const taskPtr = args[3], errPtr = args[4];
            const idn = t2id.get(taskPtr.toString());
            if (!idn) return;
            try {
                const task = new ObjC.Object(taskPtr);
                const resp = task.response;
                if (resp && !resp.isNull()) {
                    const url = S(resp.URL.absoluteString());
                    if (!url.includes(FILTER_DOMAIN)) return;
                    console.log(`[${idn}] ← ${resp.statusCode()} ${url}`);
                    const h = D(resp.allHeaderFields());
                    if (Object.keys(h).length) console.log('    • 头部:', JSON.stringify(h));
                }
                if (errPtr && !errPtr.isNull()) {
                    const E = new ObjC.Object(errPtr);
                    console.log('    • 错误:', S(E.localizedDescription));
                }
            } catch (e) { console.log('[! finish]', e); }
        }
    }
});

console.log('✅ 仅拦截并打印包含 ' + FILTER_DOMAIN + ' 的请求与响应');
