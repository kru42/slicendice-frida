// overrides.ts
function overrideConstructor(clazz, overloadSig, callback) {
    const ctor = clazz.$init.overload(...overloadSig);
    clazz.$init.overload(...overloadSig).implementation = function (...args) {
        return callback.call(this, ctor, ...args);
    };
}

function overrideMethod(clazz, methodName, overloadSig, callback) {
    const method = clazz[methodName].overload(...overloadSig);
    clazz[methodName].overload(...overloadSig).implementation = function (...args) {
        return callback.call(this, method, ...args);
    };
}

export { overrideConstructor, overrideMethod };
