if (!ObjC.available) {
    console.log('⚠️ ObjC 运行时不可用，脚本退出');
}

// 安全地把 ObjC 对象转成 JS 字符串
function safeStr(obj) {
    try {
        if (!obj || obj.isNull()) return '';
        return obj.toString();
    } catch (e) {
        return '';
    }
}

// 安全地把 NSDictionary 转成 JS 对象
function safeDict(dict) {
    var out = {};
    if (!dict || dict.isNull()) return out;
    try {
        var keys = dict.allKeys();
        for (var i = 0; i < keys.count(); i++) {
            var k = keys.objectAtIndex_(i);
            var v = dict.objectForKey_(k);
            var ks = safeStr(k), vs = safeStr(v);
            if (ks) out[ks] = vs;
        }
    } catch (e) { /* 忽略 */ }
    return out;
}

// 拦截 NSURLSessionTask resume，打印请求
Interceptor.attach(ObjC.classes.NSURLSessionTask['- resume'].implementation, {
    onEnter: function (args) {
        try {
            var task = new ObjC.Object(args[0]);
            // originalRequest 有时为 null，试试 currentRequest
            var req = task.currentRequest() || task.originalRequest();
            if (!req || req.isNull()) return;

            var method = safeStr(req.HTTPMethod()) || 'GET';
            var url = safeStr(req.URL() && req.URL().absoluteString());
            console.log('[→ 请求] ' + method + ' ' + url);

            var hdr = safeDict(req.allHTTPHeaderFields());
            if (Object.keys(hdr).length)
                console.log('    • 头部:', JSON.stringify(hdr));

            var body = req.HTTPBody();
            if (body && !body.isNull()) {
                var bstr = ObjC.classes.NSString.alloc()
                    .initWithData_encoding_(body, 4);
                console.log('    • 请求体:', safeStr(bstr));
            }
        } catch (e) {
            console.log('[! 请求日志出错]', e.message || e);
        }
    }
});

// 通用：给指定 selector 的 completionHandler block 打补丁
function hookCompletion(sel) {
    var klass = ObjC.classes.NSURLSession;
    if (!(sel in klass)) return;

    Interceptor.attach(klass[sel].implementation, {
        onEnter: function (args) {
            try {
                var block = args[3];
                if (!block || block.isNull()) return;

                // block 内部结构：offset 0x10(=2*pointerSize) 是 invoke 指针
                var invokePtr = Memory.readPointer(block.add(Process.pointerSize * 2));
                if (invokePtr.isNull()) return;

                Interceptor.attach(invokePtr, {
                    onEnter: function (cbArgs) {
                        try {
                            // cbArgs[1]=NSData *, cbArgs[2]=NSURLResponse *, cbArgs[3]=NSError *
                            var dataPtr = cbArgs[1];
                            var responsePtr = cbArgs[2];
                            var errorPtr = cbArgs[3];

                            if (responsePtr && !responsePtr.isNull()) {
                                var resp = new ObjC.Object(responsePtr);
                                var status = resp.statusCode && resp.statusCode();
                                var url = safeStr(resp.URL && resp.URL().absoluteString);
                                console.log('[← 响应] ' + (status || '') + ' ' + url);

                                var rh = safeDict(resp.allHeaderFields && resp.allHeaderFields());
                                if (Object.keys(rh).length)
                                    console.log('    • 头部:', JSON.stringify(rh));
                            }

                            if (dataPtr && !dataPtr.isNull()) {
                                var dataObj = new ObjC.Object(dataPtr);
                                var bodyStr = ObjC.classes.NSString.alloc()
                                    .initWithData_encoding_(dataObj, 4);
                                console.log('    • 响应体:', safeStr(bodyStr));
                            }

                            if (errorPtr && !errorPtr.isNull()) {
                                var errObj = new ObjC.Object(errorPtr);
                                console.log('    • 错误:', safeStr(errObj.localizedDescription && errObj.localizedDescription()));
                            }
                        } catch (e) {
                            console.log('[! 回调日志出错]', e.message || e);
                        }
                    }
                });
            } catch (e) {
                console.log('[! Hook 完成回调失败]', sel, e.message || e);
            }
        }
    });
}

// 针对两种最常用的 API 做 hook
hookCompletion('- dataTaskWithRequest:completionHandler:');
hookCompletion('- dataTaskWithURL:completionHandler:');

console.log('✅ HTTP 请求/响应 日志注入完成');