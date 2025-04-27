// 🚀 超精准扫描 PX Token生成方法的 Frida脚本
// 用来定位返回 base64 长字符串的方法！

if (ObjC.available) {
    console.log("🚀 Start PX Scanner...");

    var MIN_LENGTH = 100;  // 过滤，返回值长度大于100个字符才打印，避免噪声

    var classes = ObjC.enumerateLoadedClassesSync();
    var pxClasses = [];

    // 第一步：找所有包含PX的类
    for (var className in classes) {
        if (className.indexOf('Perimeter') !== -1) {
            pxClasses.push(className);
        }
    }

    console.log("🎯 Found PX Classes:", pxClasses.length);

    // 第二步：hook每个类的所有实例方法
    pxClasses.forEach(function (className) {
        try {
            var klass = ObjC.classes[className];
            var methods = klass.$methods;
            methods.forEach(function (methodName) {
                if (methodName.startsWith('-')) {  // 只hook实例方法
                    try {
                        var impl = klass[methodName].implementation;
                        Interceptor.attach(impl, {
                            onLeave: function (retval) {
                                if (retval.isNull()) return;

                                var result;
                                try {
                                    result = new ObjC.Object(retval).toString();
                                } catch (e) {
                                    return;
                                }

                                // 过滤，只打印长且像base64的返回值
                                if (result && result.length > MIN_LENGTH && /^[A-Za-z0-9+/=]+$/.test(result)) {
                                    console.log("\n🚀 Possible PX Token Found!");
                                    console.log("  📌 Class:", className);
                                    console.log("  📌 Method:", methodName);
                                    console.log("  🛡️ Token (base64):", result);
                                }
                            }
                        });
                    } catch (e) {
                        // 某些方法可能不能attach，直接跳过
                    }
                }
            });
        } catch (e) {
            // 某些类不能attach，跳过
        }
    });

} else {
    console.log("❌ Objective-C runtime not available!");
}