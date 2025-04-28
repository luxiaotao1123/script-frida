// http-hook-complete.js
; (function () {
    if (!ObjC.available) {
        console.error("❌ ObjC Runtime 不可用");
        return;
    }
    console.log("🔌 http-hook-complete.js loaded");

    // —— 工具函数 —— //
    const TARGET = "textnow.me";
    function safe(o) { try { if (!o || o.isNull()) return ''; return o.toString(); } catch { return ''; } }
    function dictToObj(d) {
        const o = {};
        if (!d || d.isNull()) return o;
        try {
            const ks = d.allKeys();
            for (let i = 0; i < ks.count(); i++) {
                const k = ks.objectAtIndex_(i), v = d.objectForKey_(k);
                o[safe(k)] = safe(v);
            }
        } catch { }
        return o;
    }

    // —— 1. AFHTTPClient sendTextNowRequest:json: —— //
    const AFHTTP = ObjC.classes.AFHTTPClient;
    if (AFHTTP && AFHTTP['- sendTextNowRequest:json:']) {
        Interceptor.attach(AFHTTP['- sendTextNowRequest:json:'].implementation, {
            onEnter(args) {
                try {
                    const method = new ObjC.Object(args[2]).toString();
                    const json = new ObjC.Object(args[3]).toString();
                    console.log(`🟢 AFHTTPClient sendTextNowRequest: method=${method}`);
                    console.log(`    • JSON  = ${json}`);
                } catch (e) { }
            }
        });
        console.log("✅ Hooked AFHTTPClient - sendTextNowRequest:json:");
    }

    // —— 2. AFHTTPClient textNowAPIRequestWithMethod:path:parameters:headers: —— //
    if (AFHTTP && AFHTTP['- textNowAPIRequestWithMethod:path:parameters:headers:']) {
        Interceptor.attach(
            AFHTTP['- textNowAPIRequestWithMethod:path:parameters:headers:'].implementation, {
            onEnter(args) {
                try {
                    const m = new ObjC.Object(args[2]).toString();
                    const p = new ObjC.Object(args[3]).toString();
                    const params = new ObjC.Object(args[4]);
                    const hdrs = new ObjC.Object(args[5]);
                    console.log(`🟡 AFHTTPClient APIRequest method=${m} path=${p}`);
                    console.log(`    • params = ${JSON.stringify(dictToObj(params))}`);
                    console.log(`    • headers= ${JSON.stringify(dictToObj(hdrs))}`);
                } catch (e) { }
            }
        });
        console.log("✅ Hooked AFHTTPClient - textNowAPIRequestWithMethod:path:parameters:headers:");
    }

    // —— 3. AFHTTPClient enqueueHTTPRequestOperation: —— //
    if (AFHTTP && AFHTTP['- enqueueHTTPRequestOperation:']) {
        Interceptor.attach(AFHTTP['- enqueueHTTPRequestOperation:'].implementation, {
            onEnter(args) {
                try {
                    const op = new ObjC.Object(args[2]);
                    const req = op.request();
                    const url = safe(req.URL().absoluteString());
                    if (!url.includes(TARGET)) return;
                    console.log(`🔵 enqueueHTTPRequestOperation → ${url}`);
                } catch (e) { }
            }
        });
        console.log("✅ Hooked AFHTTPClient - enqueueHTTPRequestOperation:");
    }

    // —— 4. AFJSONRequestOperation responseJSON —— //
    const AFJ = ObjC.classes.AFJSONRequestOperation;
    if (AFJ && AFJ['- responseJSON']) {
        Interceptor.attach(AFJ['- responseJSON'].implementation, {
            onLeave(ret) {
                try {
                    const op = this;  // AFJSONRequestOperation*
                    const req = new ObjC.Object(op.request());
                    const url = safe(req.URL().absoluteString());
                    if (!url.includes(TARGET)) return;
                    const js = new ObjC.Object(ret);
                    console.log(`🟣 AFJSONRequestOperation responseJSON ← ${url}`);
                    console.log(`    • JSON = ${js.toString()}`);
                } catch (e) { }
            }
        });
        console.log("✅ Hooked AFJSONRequestOperation - responseJSON");
    }

    // —— 保留：NSURLSession hooks —— //
    //（如果你也想捕 NSURLSession，可在此重用之前给你的脚本——略）

    // —— 保留：NSURLConnection hooks —— //
    //（同上，可自行加 NSURLConnection 逻辑）

    console.log("🎯 All AFNetworking hooks installed — watching textnow.me traffic.");
})();