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

    // —— 2. Hook AFJSONRequestOperation JSONRequestOperationWithRequest:success:failure: ——
    const AFJR = ObjC.classes.AFJSONRequestOperation;
    const jrSel = "+ JSONRequestOperationWithRequest:success:failure:";
    if (AFJR && AFJR[jrSel]) {
        Interceptor.attach(AFJR[jrSel].implementation, {
            onEnter(args) {
                try {
                    const req = new ObjC.Object(args[2]);
                    const url = req.URL().absoluteString().toString();
                    if (!url.includes("textnow.me")) return;
                    const id = getId(url);

                    // wrap success
                    const origSuc = new ObjC.Block(args[3]);
                    args[3] = ObjC.Block({
                        retType: 'void',
                        argTypes: ['object', 'object', 'object'],
                        implementation: function (request, response, JSON) {
                            console.log(`[${id}] 🟦 <<=== responseJSON @ ${url}`);
                            console.log("    •", JSON.toString());
                            origSuc(request, response, JSON);
                        }
                    });

                    // wrap failure
                    const origFail = new ObjC.Block(args[4]);
                    args[4] = ObjC.Block({
                        retType: 'void',
                        argTypes: ['object', 'object'],
                        implementation: function (request, error) {
                            console.log(`[${id}] 🟥 <<=== JSON Failure @ ${url}`);
                            console.log("    • Error:", safeStr(error.localizedDescription));
                            origFail(request, error);
                        }
                    });
                } catch (e) { }
            }
        });
        console.log("✅ Hooked AFJSONRequestOperation " + jrSel);
    }

    // —— 3. JSON＋Backtrace 兜底 —— 
    const JS = ObjC.classes.NSJSONSerialization;
    const SEL = "+ JSONObjectWithData:options:error:";
    if (JS && JS[SEL]) {
        Interceptor.attach(JS[SEL].implementation, {
            onEnter(args) { this.data = new ObjC.Object(args[2]); },
            onLeave(ret) {
                try {
                    if (ret.isNull()) return;
                    const dict = new ObjC.Object(ret);
                    if (!dict.isKindOfClass_(ObjC.classes.NSDictionary)) return;
                    // 检查聊天标识
                    const keys = dict.allKeys();
                    let isChat = false;
                    for (let i = 0; i < keys.count(); i++) {
                        if (keys.objectAtIndex_(i).toString() === "messages") {
                            isChat = true; break;
                        }
                    }
                    if (!isChat) return;
                    const txt = ObjC.classes.NSString
                        .alloc()
                        .initWithData_encoding_(this.data, 4)
                        .toString();
                    const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .slice(0, 8)
                        .map(addr => DebugSymbol.fromAddress(addr).toString())
                        .join("\n");

                    console.log(" 🟦<<=== " + txt);
                    // console.log("🔍 [Origin Backtrace]\n" + bt + "\n—");
                } catch { }
            }
        });
        console.log("✅ JSON＋Backtrace hook 安装完毕");
    }


    console.log('🎯 combined-http-hook.js loaded');
})();