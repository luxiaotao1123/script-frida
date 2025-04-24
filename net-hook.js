/* ========== 0. 环境检查 ========== */
if (!ObjC.available) {
    console.log('⚠️ ObjC 不可用');
    throw new Error('依赖 ObjC 环境');
}

/* ========== 1. 工具函数 ========== */
/**
 * 安全转换为字符串（处理空值和异常）
 * @param {any} obj - 输入对象
 * @returns {string} 转换后的字符串
 */
function safeToString(obj) {
    try {
        return (!obj || obj.isNull()) ? '' : obj.toString();
    } catch (_) {
        return '';
    }
}

/**
 * 将 NSDictionary 转换为 JS 对象
 * @param {NSDictionary} dict - 输入字典
 * @returns {Object} 转换后的对象
 */
function dictToObject(dict) {
    const result = {};
    if (!dict || dict.isNull()) return result;
    try {
        const keys = dict.allKeys();
        for (let i = 0; i < keys.count(); i++) {
            const key = keys.objectAtIndex_(i);
            const value = dict.objectForKey_(key);
            const keyStr = safeToString(key);
            const valueStr = safeToString(value);
            if (keyStr) result[keyStr] = valueStr;
        }
    } catch (_) { /* 忽略转换错误 */ }
    return result;
}

/* ========== 2. 全局映射管理器 ========== */
let nextTaskId = 1;
const taskIdMap = new Map();  // 任务指针 -> ID
const blockIdMap = new Map(); // Block 指针 -> 任务ID

/**
 * 获取或生成唯一任务ID
 * @param {ObjC.Object} task - NSURLSessionTask 对象
 * @returns {number} 任务ID
 */
function getTaskId(task) {
    const taskHandle = task.handle.toString();
    let id = taskIdMap.get(taskHandle);
    if (!id) {
        id = nextTaskId++;
        taskIdMap.set(taskHandle, id);
    }
    return id;
}

/* ========== 3. 拦截请求（-resume 方法） ========== */
Interceptor.attach(
    ObjC.classes.NSURLSessionTask['- resume'].implementation,
    {
        onEnter(args) {
            try {
                const task = new ObjC.Object(args[0]);
                const taskId = getTaskId(task);
                const request = task.currentRequest() || task.originalRequest();
                if (!request || request.isNull()) return;

                // 打印基础信息
                const method = safeToString(request.HTTPMethod()) || 'GET';
                const url = safeToString(request.URL()?.absoluteString());
                console.log(`[${taskId}] → ${method} ${url}`);

                // 打印请求头
                const headers = dictToObject(request.allHTTPHeaderFields());
                if (Object.keys(headers).length) {
                    console.log('    • 头部:', JSON.stringify(headers));
                }

                // 打印请求体
                const requestBody = request.HTTPBody();
                if (requestBody && !requestBody.isNull()) {
                    const bodyString = ObjC.classes.NSString.alloc()
                        .initWithData_encoding_(requestBody, 4);
                    console.log('    • 请求体:', safeToString(bodyString));
                }
            } catch (error) {
                console.log('[! 请求打印异常]', error);
            }
        }
    }
);

/* ========== 4. 拦截回调（completionHandler） ========== */
/**
 * 钩住指定的 NSURLSession 方法
 * @param {string} selectorName - 方法名（如 '-dataTaskWithRequest:completionHandler:'）
 */
function hookCompletionHandler(selectorName) {
    const NSURLSessionClass = ObjC.classes.NSURLSession;
    if (!(selectorName in NSURLSessionClass)) return;

    const handledInvokers = new Set(); // 防止重复挂钩

    Interceptor.attach(NSURLSessionClass[selectorName].implementation, {
        onEnter(args) {
            this.blockPtr = args[3]; // 保存 completionHandler 的 block 指针
        },
        onLeave(returnValue) {
            const block = this.blockPtr;
            if (!block || block.isNull()) return;

            // 绑定 block 与任务ID
            const taskId = getTaskId(new ObjC.Object(returnValue));
            blockIdMap.set(block.toString(), taskId);

            // 获取 block 的实际调用函数指针
            const invokerAddress = Memory.readPointer(block.add(Process.pointerSize * 2));
            if (invokerAddress.isNull() || handledInvokers.has(invokerAddress.toString())) return;
            handledInvokers.add(invokerAddress.toString());

            // 挂钩 block 回调
            Interceptor.attach(invokerAddress, {
                onEnter(blockArgs) {
                    const taskId = blockIdMap.get(block.toString());
                    if (!taskId) return;

                    try {
                        const responseData = blockArgs[1];
                        const response = blockArgs[2];
                        const error = blockArgs[3];

                        // 打印响应状态
                        if (response && !response.isNull()) {
                            const responseObj = new ObjC.Object(response);
                            const statusCode = responseObj.statusCode?.();
                            const responseUrl = safeToString(responseObj.URL?.()?.absoluteString());
                            console.log(`[${taskId}] ← ${statusCode} ${responseUrl}`);

                            // 打印响应头
                            const responseHeaders = dictToObject(responseObj.allHeaderFields?.());
                            if (Object.keys(responseHeaders).length) {
                                console.log('    • 头部:', JSON.stringify(responseHeaders));
                            }
                        }

                        // 打印响应体
                        if (responseData && !responseData.isNull()) {
                            const bodyString = ObjC.classes.NSString.alloc()
                                .initWithData_encoding_(new ObjC.Object(responseData), 4);
                            if (bodyString?.length() > 0) {
                                console.log('    • 响应体:', safeToString(bodyString));
                            }
                        }

                        // 打印错误
                        if (error && !error.isNull()) {
                            const errorObj = new ObjC.Object(error);
                            const errorDesc = safeToString(errorObj.localizedDescription?.());
                            console.log('    • 错误:', errorDesc);
                        }
                    } catch (error) {
                        console.log('[! 回调处理异常]', error);
                    }
                }
            });
        }
    });
}

// 钩住两种常见方法
hookCompletionHandler('-dataTaskWithRequest:completionHandler:');
hookCompletionHandler('-dataTaskWithURL:completionHandler:');

/* ========== 5. 拦截 delegate 回调（objc_msgSend） ========== */
const msgSend = Module.getExportByName(null, 'objc_msgSend');
const SELECTOR_DATA = ObjC.selector('URLSession:dataTask:didReceiveData:');
const SELECTOR_FINISH = ObjC.selector('URLSession:task:didCompleteWithError:');

Interceptor.attach(msgSend, {
    onEnter(args) {
        const selectorPointer = args[1];

        // 处理分块数据回调
        if (selectorPointer.equals(SELECTOR_DATA)) {
            const taskPointer = args[3];
            const dataPointer = args[4];
            const taskId = taskIdMap.get(taskPointer.toString());

            if (!taskId || !dataPointer || dataPointer.isNull()) return;

            const responseBody = ObjC.classes.NSString.alloc()
                .initWithData_encoding_(new ObjC.Object(dataPointer), 4);
            if (responseBody?.length() > 0) {
                console.log(`[${taskId}] ← (chunk)    • 响应体:`, safeToString(responseBody));
            }
        }

        // 处理完成回调
        else if (selectorPointer.equals(SELECTOR_FINISH)) {
            const taskPointer = args[3];
            const errorPointer = args[4];
            const taskId = taskIdMap.get(taskPointer.toString());
            if (!taskId) return;

            try {
                const task = new ObjC.Object(taskPointer);
                const response = task.response?.();

                if (response && !response.isNull()) {
                    const statusCode = response.statusCode?.();
                    const responseUrl = safeToString(response.URL?.()?.absoluteString());
                    console.log(`[${taskId}] ← ${statusCode} ${responseUrl}`);

                    const responseHeaders = dictToObject(response.allHeaderFields?.());
                    if (Object.keys(responseHeaders).length) {
                        console.log('    • 头部:', JSON.stringify(responseHeaders));
                    }
                }

                if (errorPointer && !errorPointer.isNull()) {
                    const errorObj = new ObjC.Object(errorPointer);
                    const errorDesc = safeToString(errorObj.localizedDescription?.());
                    console.log('    • 错误:', errorDesc);
                }
            } catch (error) {
                console.log('[! delegate 完成回调异常]', error);
            }
        }
    }
});

console.log('✅ 优化完成：兼容 delegate 和 completion，性能稳定');