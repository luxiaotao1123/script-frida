// ========== 配置区 ==========
// 改这里：你的模块名（通常就是App名）
const moduleName = "TextNow";

// 改这里：Ghidra里面你看到的偏移
const ghidraOffsetHex = "0x10031cf20";

// ========== 自动attach逻辑 ==========

function hookGrpcSend() {
    const modules = Process.enumerateModules();
    const targetModule = modules.find(m => m.name.indexOf(moduleName) >= 0);

    if (!targetModule) {
        console.error(`❌ 找不到模块 ${moduleName}`);
        return;
    }

    const base = ptr(targetModule.base);
    const ghidraOffset = ptr(ghidraOffsetHex);
    const realAddress = base.sub('0x100000000').add(ghidraOffset);

    console.log(`✅ 成功找到模块 ${moduleName}`);
    console.log(`✅ 基址: ${base}`);
    console.log(`✅ 偏移: ${ghidraOffset}`);
    console.log(`✅ 实际地址: ${realAddress}`);

    Interceptor.attach(realAddress, {
        onEnter: function (args) {
            try {
                const param_2 = args[1];

                if (param_2.isNull()) {
                    console.log("⚠️ param_2为空，跳过");
                    return;
                }

                const dataPtr = param_2.readPointer();
                const length = param_2.add(Process.pointerSize).readU64();

                if (dataPtr.isNull() || length === 0) {
                    console.log("⚠️ 数据为空，跳过");
                    return;
                }

                const rawData = Memory.readByteArray(dataPtr, length);

                console.log("\n🚀 捕获到gRPC发送数据:");
                console.log("长度:", length, "bytes");

                console.log(hexdump(rawData, {
                    offset: 0,
                    length: length,
                    header: true,
                    ansi: true
                }));

                try {
                    const asString = Memory.readUtf8String(dataPtr, length);
                    console.log("可能的文本内容:", asString);
                } catch (e) {
                    console.log("🛑 不是有效的UTF-8字符串");
                }

            } catch (e) {
                console.error("❌ Hook处理失败:", e);
            }
        }
    });
}

setImmediate(hookGrpcSend);