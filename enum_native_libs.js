Java.perform(function () {
    console.log("Starting script to monitor native library loading...");

    // Hook dlopen
    var dlopen = Module.findExportByName(null, "dlopen");
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                var libraryName = Memory.readUtf8String(args[0]);
                console.log("Library Loaded via dlopen: " + libraryName);
            }
        });
    } else {
        console.error("dlopen not found.");
    }

    // Hook android_dlopen_ext (used in modern Android systems)
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    if (android_dlopen_ext) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function (args) {
                var libraryName = Memory.readUtf8String(args[0]);
                console.log("Library Loaded via android_dlopen_ext: " + libraryName);
            }
        });
    } else {
        console.error("android_dlopen_ext not found.");
    }

    // Hook JNI_OnLoad for funsies
    var modules = Process.enumerateModules();
    modules.forEach(function (module) {
        var exports = module.enumerateExports();
        exports.forEach(function (exp) {
            if (exp.name === "JNI_OnLoad") {
                Interceptor.attach(exp.address, {
                    onEnter: function (args) {
                        console.log("JNI_OnLoad triggered in module: " + module.name);
                    }
                });
            }
        });
    });

    console.log("Script loaded. Monitoring native library loading...");
});
