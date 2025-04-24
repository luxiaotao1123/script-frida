/* ======================================================
 * 0. 运行时检查
 * ====================================================== */
if (!ObjC.available) {
    console.log('⚠️ ObjC 运行时不可用，脚本退出');
}

/* ======================================================
 * 1. 工具函数
 * ====================================================== */
function safeStr(o) {
    try { return (!o || o.isNull()) ? '' : o.toString(); } catch (_) { return ''; }
}
function safeDict(dict) {
    const out = {};
    if (!dict || dict.isNull()) return out;
    try {
        const keys = dict.allKeys();
        for (let i = 0; i < keys.count(); i++) {
            const k = keys.objectAtIndex_(i);
            const v = dict.objectForKey_(k);
            const ks = safeStr(k), vs = safeStr(v);
            if (ks) out[ks] = vs;
        }
    } catch (_) { }
    return out;
}

/* ======================================================
 * 2. 全局 ID 映射
 * ====================================================== */
let nextId = 1;
const task2id = new Map();               // taskPtrStr  -> reqId
const block2id = new Map();               // blockPtrStr -> reqId
function ensureIdForTask(taskObj) {
    const key = taskObj.handle.toString();
    let id = task2id.get(key);
    if (!id) { id = nextId++; task2id.set(key, id); }
    return id;
}

/* ======================================================
 * 3. 拦截 -resume 打印请求
 * ====================================================== */
Interceptor.attach(
    ObjC.classes.NSURLSessionTask['- resume'].implementation,
    {
        onEnter(args) {
            try {
                const task = new ObjC.Object(args[0]);
                const id = ensureIdForTask(task);

                const req = task.currentRequest() || task.originalRequest();
                if (!req || req.isNull()) return;

                const method = safeStr(req.HTTPMethod()) || 'GET';
                const url = safeStr(req.URL() && req.URL().absoluteString());
                console.log(`[${id}] → ${method} ${url}`);

                const hdr = safeDict(req.allHTTPHeaderFields());
                if (Object.keys(hdr).length)
                    console.log('    • 头部:', JSON.stringify(hdr));

                const body = req.HTTPBody();
                if (body && !body.isNull()) {
                    const bodyStr = ObjC.classes.NSString.alloc()
                        .initWithData_encoding_(body, 4);
                    console.log('    • 请求体:', safeStr(bodyStr));
                }
            } catch (e) {
                console.log('[! 请求日志出错]', e);
            }
        }
    });

/* ======================================================
 * 4. completion-handler 回调（与你原脚本相同）
 * ====================================================== */
function hookCompletion(sel) {
    const cls = ObjC.classes.NSURLSession;
    if (!(sel in cls)) return;

    const attached = new Set();            // 避免重复 attach 同一 invoke

    Interceptor.attach(cls[sel].implementation, {
        onEnter(args) { this.blockPtr = args[3]; },
        onLeave(retval) {
            try {
                const blk = this.blockPtr;
                if (!blk || blk.isNull()) return;

                const blkKey = blk.toString();
                const id = ensureIdForTask(new ObjC.Object(retval));
                block2id.set(blkKey, id);

                const invokePtr = Memory.readPointer(blk.add(Process.pointerSize * 2));
                if (invokePtr.isNull() || attached.has(invokePtr.toString())) return;
                attached.add(invokePtr.toString());

                Interceptor.attach(invokePtr, {
                    onEnter(cbArgs) {
                        const id = block2id.get(blkKey);
                        if (!id) return;
                        try {
                            const dataPtr = cbArgs[1];
                            const respPtr = cbArgs[2];
                            const errPtr = cbArgs[3];

                            if (respPtr && !respPtr.isNull()) {
                                const resp = new ObjC.Object(respPtr);
                                const status = resp.statusCode && resp.statusCode();
                                const url = safeStr(resp.URL && resp.URL().absoluteString());
                                console.log(`[${id}] ← ${status || ''} ${url}`);

                                const rh = safeDict(resp.allHeaderFields && resp.allHeaderFields());
                                if (Object.keys(rh).length)
                                    console.log('    • 头部:', JSON.stringify(rh));
                            }

                            if (dataPtr && !dataPtr.isNull()) {
                                const bodyStr = ObjC.classes.NSString.alloc()
                                    .initWithData_encoding_(new ObjC.Object(dataPtr), 4);
                                if (bodyStr && bodyStr.length() > 0)
                                    console.log('    • 响应体:', safeStr(bodyStr));
                            }

                            if (errPtr && !errPtr.isNull()) {
                                const errObj = new ObjC.Object(errPtr);
                                console.log('    • 错误:',
                                    safeStr(errObj.localizedDescription && errObj.localizedDescription()));
                            }
                        } catch (e) { console.log('[! 回调日志出错]', e); }
                    }
                });
            } catch (_) { }
        }
    });
}

hookCompletion('- dataTaskWithRequest:completionHandler:');
hookCompletion('- dataTaskWithURL:completionHandler:');

/* ======================================================
 * 5. delegate-style 回调 (补 TextNow 漏响应)
 * ====================================================== */
const msgSend = Module.getExportByName(null, 'objc_msgSend');
const sel_data = ObjC.selector('URLSession:dataTask:didReceiveData:');
const sel_finish = ObjC.selector('URLSession:task:didCompleteWithError:');

Interceptor.attach(msgSend, {
    onEnter(args) {
        const cmdPtr = args[1];

        /* ---- didReceiveData ---- */
        if (cmdPtr.equals(sel_data)) {
            try {
                const taskPtr = args[3];
                const dataPtr = args[4];
                const id = task2id.get(taskPtr.toString());
                if (!id || !dataPtr || dataPtr.isNull()) return;

                const bodyStr = ObjC.classes.NSString.alloc()
                    .initWithData_encoding_(new ObjC.Object(dataPtr), 4);
                if (bodyStr && bodyStr.length() > 0)
                    console.log(`[${id}] ← (chunk)    • 响应体:`, safeStr(bodyStr));
            } catch (e) { console.log('[! delegate data 回调出错]', e); }
        }

        /* ---- didCompleteWithError ---- */
        else if (cmdPtr.equals(sel_finish)) {
            try {
                const taskPtr = args[3];
                const errPtr = args[4];
                const id = task2id.get(taskPtr.toString());
                if (!id) return;

                const taskObj = new ObjC.Object(taskPtr);
                const respObj = taskObj.response && taskObj.response();
                if (respObj && !respObj.isNull()) {
                    const status = respObj.statusCode && respObj.statusCode();
                    const url = safeStr(respObj.URL && respObj.URL().absoluteString());
                    console.log(`[${id}] ← ${status || ''} ${url}`);

                    const rh = safeDict(respObj.allHeaderFields && respObj.allHeaderFields());
                    if (Object.keys(rh).length)
                        console.log('    • 头部:', JSON.stringify(rh));
                }

                if (errPtr && !errPtr.isNull()) {
                    const errObj = new ObjC.Object(errPtr);
                    console.log('    • 错误:',
                        safeStr(errObj.localizedDescription && errObj.localizedDescription()));
                }
            } catch (e) { console.log('[! delegate finish 回调出错]', e); }
        }
    }
});

console.log('✅ HTTP 请求/响应 日志注入完成（completion + delegate，带 reqId）');