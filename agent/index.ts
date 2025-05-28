import { log } from "./logger.js";

let mainInstance = null;

// TODO: Make sure achievements don't phone home
function offlinePatch() {
    // Disable the leaderboard and unlock all game modes
    log("Disabling leaderboard and unlocking all game modes...");

    const unutilClass = "com.tann.dice.gameplay.progress.chievo.unlock.UnUtil";
    const leaderboardClass = "com.tann.dice.gameplay.leaderboard.Leaderboard";
    const UnUtil = Java.use(unutilClass);
    const Leaderboard = Java.use(leaderboardClass);

    log(`UnUtil class: ${unutilClass}`);
    log(`Leaderboard class: ${leaderboardClass}`);

    // Hook the UnUtil class to disable the isLocked method
    const unutilCtor = UnUtil.$init.overload();
    UnUtil.$init.overload().implementation = function () {
        log("UnUtil instance created: " + this);
        return unutilCtor.call(this);
    };

    // hook the isLocked method at class level
    UnUtil.isLocked.implementation = function (unlockable) {
        return false;
    };

    log("Successfully hooked UnUtil.isLocked()");

    // TODO: We probably wanna patch out the leaderboard menus altogether at some point
    log("Hooking Leaderboard.makeGetRequest and Leaderboard.postScore...");
    const leaderboardCtor = Leaderboard.$init.overload(
        'java.lang.String',
        'com.badlogic.gdx.graphics.Color',
        'java.lang.String',
        'java.lang.String',
        'int',
        'boolean'
    );

    Leaderboard.$init.overload(
        'java.lang.String',
        'com.badlogic.gdx.graphics.Color',
        'java.lang.String',
        'java.lang.String',
        'int',
        'boolean'
    ).implementation = function (str, color, str2, str3, i, z) {
        log(`Leaderboard created: name=${str}, color=${color}, url=${str2}, scoreName=${str3}, requiredScore=${i}, keepHighest=${z}`);
        return leaderboardCtor.call(this, str, color, str2, str3, i, z);
    };

    Leaderboard.makeGetRequest.implementation = function () {
        log("Leaderboard.makeGetRequest called");
        return;
    };

    Leaderboard.postScore.implementation = function () {
        log("Leaderboard.postScore called");
        return;
    };
}

// function setupCustomMode() {
//     const DemoMode = Java.use("com.tann.dice.gameplay.mode.general.DemoMode");
//     const DebugConfig = Java.use("com.tann.dice.gameplay.context.config.misc.DebugConfig");
//     const Arrays = Java.use("java.util.Arrays");
//     const StandardButton = Java.use("com.tann.dice.util.ui.standardButton.StandardButton");

//     // Hook the makeStartButton method to create a custom mode start button
//     DebugConfig.makeStartButton.implementation = function (z) {
//         log("makeStartButton() hooked for DebugConfig");
//         return StandardButton.$new.overload('java.lang.String').call(StandardButton, "[green]Custom Mode");
//     };

//     DemoMode.makeAllConfigs.implementation = function () {
//         log("Overriding DemoMode config with DebugConfig");
//         const dbgConfig = DebugConfig.$new(); // Create DebugConfig instance (as dummy)

//         // Create a Java array of ContextConfig (superclass of DebugConfig)
//         const ContextConfigArray = Java.array('com.tann.dice.gameplay.context.config.ContextConfig', [dbgConfig]);
//         return Arrays.asList(ContextConfigArray);
//     };
// }

function setupGameplayHooks() {
    // FIXME: Hook game start, this isn't it
    const TitleScreen = Java.use("com.tann.dice.screens.titleScreen.TitleScreen");
    TitleScreen.$init.overload().implementation = function () {
        const instance = this.$init();
        TitleScreen.selectMode.implementation = function () {
            log("Dungeon is starting...")
            showPopup("pet me uwu");
            return this.startGame();
        };
        return instance;
    };

    // Hook phase deserialization
    const Phase = Java.use("com.tann.dice.gameplay.phase.Phase");

    log("Setting up gameplay hooks...")

    Phase.actuallyDeserialise.overload('java.lang.String', 'boolean').implementation = function (str, z) {
        const deserializedPhase = this.actuallyDeserialise(str, z);
        log(`Deserialized phase object: ${deserializedPhase.toString()}`);
        return deserializedPhase;
    }
}

function setupMiscHooks() {
    // Skip splash screen
    const SplashDraw = Java.use("com.tann.dice.screens.splashScreen.SplashDraw");
    SplashDraw.draw.overload('com.tann.dice.screens.splashScreen.SplashDraw$SplashType').implementation = function (type) {
        if (type == "Loading") {
            return;
        }
        this.draw.call(this, type);
    };

    // const DebugUtilsUseful = Java.use('com.tann.dice.util.DebugUtilsUseful');
    // const heroStrings = DebugUtilsUseful.getHeroStrings(true);
}

function setupLoggingHook() {
    const TannLog = Java.use("com.tann.dice.util.TannLog");

    TannLog.log.overload('java.lang.String').implementation = function (message) {
        log(`[TANN] ${message}`);
    };

    TannLog.error.overload('java.lang.String').implementation = function (message) {
        log(`[ERR] ${message}`);
    };
}

function setupGraphDrawingHooks() {
    const GraphUtils = Java.use("com.tann.dice.screens.graph.GraphUtils");

    // // Toggle Actor debug mode for all Actor class instances, just because
    // const Actor = Java.use("com.badlogic.gdx.scenes.scene2d.Actor");
    // Actor.$init.overload().implementation = function () {
    //     const instance = this.$init();
    //     this.debug.value = true;
    //     log(`[DEBUG] Actor initialized and debug mode set`);
    //     return instance;
    // };

    GraphUtils.make.implementation = function (list, i, z, z2, graphUpdate) {
        return this.make.call(this, list, i, z, z2, graphUpdate);
    }
}

// Draws a popup at the center of the screen
function showPopup(str) {
    mainInstance.getCurrentScreen().showDialog(str);
}

// messy
function drawTextBox(str, x, y,) {
    // const TextBox = Java.use("com.tann.dice.util.ui.TextBox");
    // const FontWrapper = Java.use("com.tann.dice.util.FontWrapper");

    //const main = mainInstance.self();
    //const font = FontWrapper.getTannFont();

    // const tb = TextBox.$new.overload(
    //     'java.lang.String',
    //     'com.tann.dice.util.FontWrapper'
    // ).call(TextBox, "Hello from Frida", font);


    // tb.setPosition(100, 200);
    // tb.setColor(GdxColor.WHITE.value);
    // log(`[DEBUG] Drawing textbox with text: ${str}, x: ${x}, y: ${y}`);
    // main.stage.value.addActor(tb);

    // log("Added TextBox to stage.");
}

Java.perform(() => {
    const Main = Java.use("com.tann.dice.Main");
    const Gdx = Java.use("com.badlogic.gdx.Gdx");

    setupLoggingHook();
    setupMiscHooks();

    // Hook the `Main` ctor
    Main.$init.overload('com.tann.dice.platform.audio.SoundHandler', 'com.tann.dice.platform.control.Control', 'boolean', 'boolean').implementation =
        function (soundHandler, control, z, z2) {
            log("[*] Main constructor called");
            const result = this.$init.call(this, soundHandler, control, z, z2);

            // Save ref to instance
            mainInstance = this;

            // Start waiting for Gdx.app to be ready
            waitForLibGDX(() => {
                log("[+] Gdx.app is now initialized");

                // Safe to call our hooks
                offlinePatch();
                //setupCustomMode();
                setupGameplayHooks();
                setupGraphDrawingHooks();
            });


            return result;
        };

    function waitForLibGDX(callback: () => void) {
        const interval = setInterval(() => {
            try {
                const app = Gdx.app.value;
                if (app !== null) {
                    clearInterval(interval);
                    callback();
                }
            } catch (err) {
                // yawn
            }
        }, 100);
    }
});