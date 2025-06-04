import { log } from "./logger.js";
import { overrideConstructor, overrideMethod } from "./utils.js";
import {
    offlinePatch,
    setupGameplayHooks,
    setupMiscHooks,
    setupLoggingHook,
    setupGraphDrawingHooks,
    showPopup,
    drawTextBox
} from "./game-hooks.js";
import { setupAutobattleHooks } from './autobattle.js';

let mainInstance = null;

Java.perform(() => {
    const Main = Java.use("com.tann.dice.Main");
    const Gdx = Java.use("com.badlogic.gdx.Gdx");

    setupLoggingHook();
    setupMiscHooks();

    overrideConstructor(Main, [
        'com.tann.dice.platform.audio.SoundHandler',
        'com.tann.dice.platform.control.Control',
        'boolean',
        'boolean'
    ], function (ctor, soundHandler, control, z, z2) {
        log("[*] Main constructor called");
        const result = ctor.call(this, soundHandler, control, z, z2);
        mainInstance = this;

        waitForLibGDX(() => {
            log("[+] Gdx.app is now initialized");
            offlinePatch();
            //setupCustomMode();
            setupGameplayHooks();
            setupGraphDrawingHooks();
            setupAutobattleHooks();
        });

        return result;
    });

    function waitForLibGDX(callback) {
        const interval = setInterval(() => {
            try {
                const app = Gdx.app.value;
                if (app !== null) {
                    clearInterval(interval);
                    callback();
                }
            } catch (_) {
                // yawn
            }
        }, 100);
    }
});

export { mainInstance };
