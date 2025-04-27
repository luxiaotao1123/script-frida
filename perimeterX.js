// === Frida脚本：TextNow注册接口逆向辅助 ===
// 目标：自动dump PX Token、Integrity Session、请求Headers
// 适配越狱或非越狱环境（必须装Frida）

if (ObjC.available) {
    console.log("🚀 Frida Script Started");

    // 辅助函数：安全读取对象
    function safeRead(obj) {
        if (!obj || obj.isNull()) return null;
        try {
            return obj.toString();
        } catch (e) {
            return null;
        }
    }

    // 枚举所有已加载类
    const classes = ObjC.enumerateLoadedClassesSync();
    let pxFound = false;
    for (const cls in classes) {
        if (cls.includes("PX") || cls.includes("PerimeterX")) {
            console.log("🔍 Found PX related class:", cls);
            pxFound = true;
        }
    }
    if (!pxFound) {
        console.log("⚠️ Warning: No obvious PX class found. May be obfuscated.");
    }

    // Hook 生成PX Authorization的方法
    function hookPXToken() {
        try {
            const PXProvider = ObjC.classes.PXTokenProvider;
            if (PXProvider) {
                Interceptor.attach(PXProvider["- generateToken"].implementation, {
                    onEnter: function (args) {
                        console.log("📦 Enter PXTokenProvider.generateToken");
                    },
                    onLeave: function (retval) {
                        const token = safeRead(new ObjC.Object(retval));
                        if (token) {
                            console.log("🛡️ [PX Authorization Token] =", token);
                        }
                    }
                });
            }
        } catch (e) {
            console.log("❌ PXToken hook failed:", e);
        }
    }

    // Hook Integrity Session 生成的地方
    function hookIntegritySession() {
        try {
            const IntegrityService = ObjC.classes.TNIntegritySessionProvider; // 假设是这个，具体名字需要你frida-trace确认
            if (IntegrityService) {
                Interceptor.attach(IntegrityService["- generateIntegritySession"].implementation, {
                    onEnter: function (args) {
                        console.log("📦 Enter TNIntegritySessionProvider.generateIntegritySession");
                    },
                    onLeave: function (retval) {
                        const session = safeRead(new ObjC.Object(retval));
                        if (session) {
                            console.log("🛡️ [TN Integrity Session] =", session);
                        }
                    }
                });
            }
        } catch (e) {
            console.log("❌ IntegritySession hook failed:", e);
        }
    }

    // Hook 所有发出的请求，dump完整Header
    function hookNSURLSession() {
        try {
            const NSURLSession = ObjC.classes.NSURLSession;
            Interceptor.attach(NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation, {
                onEnter: function (args) {
                    const request = new ObjC.Object(args[2]);
                    const url = safeRead(request.URL());
                    const headers = request.allHTTPHeaderFields();
                    if (url && headers) {
                        console.log("🌐 [HTTP Request] URL:", url);
                        console.log("📝 [HTTP Headers Dump]:");
                        const enumerator = headers.keyEnumerator();
                        let key;
                        while ((key = enumerator.nextObject()) !== null) {
                            const value = headers.objectForKey_(key);
                            console.log(`  ${safeRead(key)}: ${safeRead(value)}`);
                        }
                        console.log("🔗 -------------------------------");
                    }
                }
            });
        } catch (e) {
            console.log("❌ NSURLSession hook failed:", e);
        }
    }

    // 启动所有hook
    hookPXToken();
    hookIntegritySession();
    hookNSURLSession();

} else {
    console.log("❌ Objective-C runtime is not available!");
}