// hook_afhttp.js
; (function () {
    if (!ObjC.available) return;
    const FA = ObjC.classes.AFHTTPClient;
    const sel = '- textNowAPIRequestWithMethod:path:parameters:headers:';
    if (!FA || !FA[sel]) {
        console.error("找不到 AFHTTPClient.textNowAPIRequestWithMethod:path:parameters:headers:");
        return;
    }

    // 简单把 NSDictionary 转成 JS 对象
    function dictToObj(d) {
        const o = {};
        try {
            const keys = d.allKeys();
            for (let i = 0; i < keys.count(); i++) {
                const k = keys.objectAtIndex_(i).toString();
                const v = d.objectForKey_(keys.objectAtIndex_(i));
                o[k] = v.toString();
            }
        } catch (e) { }
        return o;
    }

    Interceptor.attach(FA[sel].implementation, {
        onEnter(args) {
            try {
                const method = new ObjC.Object(args[2]).toString();
                const path = new ObjC.Object(args[3]).toString();
                const params = new ObjC.Object(args[4]);
                console.log(`🔸 [TextNowAPI] ${method} ${path}`);
                const p = dictToObj(params);
                if (Object.keys(p).length) console.log('    • params =', JSON.stringify(p));
            } catch (e) { }
        }
    });

    // Hook AFJSONRequestOperation 的解析，打印响应 JSON
    const AJO = ObjC.classes.AFJSONRequestOperation;
    const rsel = '- responseJSON';
    if (AJO && AJO[rsel]) {
        Interceptor.attach(AJO[rsel].implementation, {
            onLeave(ret) {
                try {
                    const obj = new ObjC.Object(ret);
                    console.log('🔹 [TextNowAPI] responseJSON =', obj.toString());
                } catch (e) { }
            }
        });
    }

    console.log("✅ hook_afhttp.js loaded — catching TextNow HTTP messages.");
})();