// json-backtrace.js
; (function () {
    if (!ObjC.available) {
        console.error("❌ ObjC Runtime 不可用");
        return;
    }
    const JS = ObjC.classes.NSJSONSerialization;
    const SEL = '+ JSONObjectWithData:options:error:';
    if (!JS[SEL]) {
        console.error('❌ 找不到 NSJSONSerialization.' + SEL);
        return;
    }

    console.log('🔍 JSON＋Backtrace hook 已安装，只打印聊天相关 JSON…');

    Interceptor.attach(JS[SEL].implementation, {
        onEnter(args) {
            this.data = new ObjC.Object(args[2]);
        },
        onLeave(ret) {
            try {
                if (ret.isNull()) return;
                const dict = new ObjC.Object(ret);
                if (!dict.isKindOfClass_(ObjC.classes.NSDictionary)) return;

                // 检查是否聊天 JSON
                const keys = dict.allKeys();
                let isChat = false;
                for (let i = 0; i < keys.count(); i++) {
                    const k = keys.objectAtIndex_(i).toString();
                    if (k === 'messages' || k === 'message') { isChat = true; break; }
                }
                if (!isChat) return;

                // 原始 JSON 文本
                const txt = ObjC.classes.NSString
                    .alloc()
                    .initWithData_encoding_(this.data, 4)
                    .toString();

                // 获取调用栈
                const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .slice(0, 8)
                    .map(addr => DebugSymbol.fromAddress(addr).toString())
                    .join('\n');

                console.log('📬 [Chat JSON]\n' + txt);
                console.log('🔍 [Origin Backtrace]\n' + bt + '\n—');
            } catch (e) {
                // ignore
            }
        }
    });
})();