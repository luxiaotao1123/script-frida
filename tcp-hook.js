// combined-http-hook.js
; (function () {
    if (!ObjC.available) return;

    // —— 通用工具 —— 
    function safeStr(o) { try { return o && !o.isNull() ? o.toString() : '' } catch { return '' } }
    function dictToObj(d) {
        const o = {};
        if (!d || d.isNull()) return o;
        try {
            const ks = d.allKeys();
            for (let i = 0; i < ks.count(); i++) {
                const k = ks.objectAtIndex_(i), v = d.objectForKey_(k);
                o[safeStr(k)] = safeStr(v);
            }
        } catch { }
        return o;
    }

    let nextId = 1;
    const idMap = new Map();

    function getId(key) {
        let id = idMap.get(key);
        if (!id) { id = nextId++; idMap.set(key, id); }
        return id;
    }

    // —— 1. 钩 AFHTTPClient.textNowAPIRequestWithMethod… —— 
    const FA = ObjC.classes.AFHTTPClient;
    const apiSel = '- textNowAPIRequestWithMethod:path:parameters:headers:';
    if (FA && FA[apiSel]) {
        Interceptor.attach(FA[apiSel].implementation, {
            onEnter(args) {
                try {
                    const method = new ObjC.Object(args[2]).toString();
                    const path = new ObjC.Object(args[3]).toString();
                    const params = new ObjC.Object(args[4]);
                    const key = method + ' ' + path;
                    const id = getId(key);
                    console.log(`\n[${id}] 🟢 ===>> ${method} ${path}`);
                    const p = dictToObj(params);
                    if (Object.keys(p).length) console.log('    • params =', JSON.stringify(p));
                } catch { }
            }
        });
        console.log('✅ Hooked AFHTTPClient ' + apiSel);
    }

    console.log('🎯 combined-http-hook.js loaded');
})();