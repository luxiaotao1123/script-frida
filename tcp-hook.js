// detect_push_ws_fixed.js
; (function () {
    if (!ObjC.available) {
        console.error("Objective-C Runtime is not available");
        return;
    }

    function tryUtf8(ptr, len) {
        try { return Memory.readUtf8String(ptr, len); }
        catch (e) { return null; }
    }

    function dump(ptr, len) {
        var txt = tryUtf8(ptr, len);
        return (txt && txt.length)
            ? txt
            : hexdump(ptr, { length: len, header: false, ansi: false });
    }

    // ─── 1. WebSocket Hooks ───────────────────────────────────────────────────────
    try {
        var WS1 = ObjC.classes.NWURLSessionWebSocketTask;
        Interceptor.attach(WS1['- receiveMessageWithCompletionHandler:'].implementation, {
            onEnter: function (args) {
                this.cb = args[2];
            },
            onLeave: function () {
                console.log("[WS:NSURLSessionWebSocketTask] Received frame");
            }
        });
        console.log("[*] Hooked NWURLSessionWebSocketTask");
    } catch (e) { }

    try {
        var WS2 = ObjC.classes['Alamofire.WebSocketRequest'];
        ObjC.enumerateLoadedClasses({
            onMatch: function (name) {
                if (name === 'Alamofire.WebSocketRequest') {
                    var C = ObjC.classes[name];
                    C.$ownMethods.forEach(function (m) {
                        if (m.indexOf("receive") !== -1) {
                            Interceptor.attach(C[m].implementation, {
                                onEnter: function () {
                                    console.log("[WS:Alamofire] " + m + " called");
                                }
                            });
                        }
                    });
                }
            },
            onComplete: function () { }
        });
        console.log("[*] Scanned Alamofire.WebSocketRequest methods");
    } catch (e) { }

    try {
        var NWWS = ObjC.classes.NWProtocolWebSocket;
        NWWS.$ownMethods.forEach(function (m) {
            if (/frame|message/i.test(m)) {
                Interceptor.attach(NWWS[m].implementation, {
                    onEnter: function () {
                        console.log("[WS:NWProtocolWebSocket] " + m);
                    }
                });
            }
        });
        console.log("[*] Scanned NWProtocolWebSocket methods");
    } catch (e) { }

    // ─── 2. POSIX / CFNetwork / TLS 兜底 ────────────────────────────────────────────
    ['read', 'recv', 'recvfrom', 'readv', 'recvmsg'].forEach(function (fn) {
        var addr = Module.findExportByName(null, fn);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.fn = fn;
                this.buf = args[1];
                this.len = parseInt(args[2]);
            },
            onLeave: function (ret) {
                var l = ret.toInt32();
                if (l > 0) {
                    console.log("[TCP:" + this.fn + "][" + l + " bytes]");
                }
            }
        });
    });

    ['CFReadStreamRead', 'CFWriteStreamWrite'].forEach(function (sym) {
        var ptr = Module.findExportByName('CFNetwork', sym);
        if (!ptr) return;
        Interceptor.attach(ptr, {
            onEnter: function (args) {
                this.buf = args[1];
                this.len = args[2].toInt32();
                this.sym = sym;
            },
            onLeave: function (ret) {
                var l = ret.toInt32();
                if (l > 0) console.log("[CFNet:" + this.sym + "][" + l + " bytes]");
            }
        });
    });

    ['SSLRead', 'SSLWrite'].forEach(function (sym) {
        var ptr = Module.findExportByName('Security', sym);
        if (!ptr) return;
        Interceptor.attach(ptr, {
            onEnter: function (args) {
                if (sym === 'SSLRead') {
                    this.bufPtr = args[1];
                    this.lenPtr = args[2];
                } else {
                    this.buf = args[1];
                    this.len = args[2].toInt32();
                }
                this.sym = sym;
            },
            onLeave: function () {
                if (this.sym === 'SSLRead') {
                    var l = this.lenPtr.readU32();
                    if (l > 0) console.log("[TLS:SSLRead][" + l + " bytes]");
                } else {
                    if (this.len > 0) console.log("[TLS:SSLWrite][" + this.len + " bytes]");
                }
            }
        });
    });

    // ─── 3. PushKit Hook ──────────────────────────────────────────────────────────
    try {
        var PKDelName = null;
        ObjC.enumerateLoadedClasses({
            onMatch: function (name) {
                var cls = ObjC.classes[name];
                if (cls && cls.$protocols &&
                    cls.$protocols.indexOf('PKPushRegistryDelegate') !== -1) {
                    PKDelName = name;
                    console.log("[FOUND] PushKit Delegate: " + name);
                }
            },
            onComplete: function () { }
        });
        if (PKDelName) {
            var sel = '- pushRegistry:didReceiveIncomingPushWithPayload:forType:withCompletionHandler:';
            var impl = ObjC.classes[PKDelName][sel];
            if (impl) {
                Interceptor.attach(impl.implementation, {
                    onEnter: function (args) {
                        console.log("[PushKit] Incoming push");
                    }
                });
            }
        }
    } catch (e) { }

    // ─── 4. UNUserNotificationCenter Hook ────────────────────────────────────────
    try {
        var center = ObjC.classes.UNUserNotificationCenter.currentNotificationCenter();
        var delegate = center.delegate();
        if (delegate) {
            var D = ObjC.classes[delegate.$className];
            var sel = '- userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:';
            if (D[sel]) {
                Interceptor.attach(D[sel].implementation, {
                    onEnter: function () {
                        console.log("[UNNotification] didReceiveNotificationResponse");
                    }
                });
            }
        }
    } catch (e) { }

    // ─── 5. UIApplicationDelegate Remote Notification ────────────────────────────
    ObjC.enumerateLoadedClasses({
        onMatch: function (name) {
            if (name.indexOf('AppDelegate') !== -1) {
                console.log("[APPDELEGATE] " + name);
            }
        },
        onComplete: function () { }
    });

    console.log("✅ detect_push_ws_fixed.js loaded. 发消息时观察哪条前缀最先出现！");
})();