// utils.ts
export function overrideConstructor(clazz, overloadSig, callback) {
    const ctor = clazz.$init.overload(...overloadSig);
    clazz.$init.overload(...overloadSig).implementation = function (...args) {
        return callback.call(this, ctor, ...args);
    };
}

export function overrideMethod(clazz, methodName, overloadSig, callback) {
    const method = clazz[methodName].overload(...overloadSig);
    clazz[methodName].overload(...overloadSig).implementation = function (...args) {
        return callback.call(this, method, ...args);
    };
}

export function clazz(name: string): Java.Wrapper {
    try {
        return Java.use(name);
    } catch (e) {
        throw new Error(`[clazz] Failed to resolve class '${name}': ${e}`);
    }
}
