import { log } from "./logger.js"
import { overrideConstructor, overrideMethod } from "./utils.js";
import { mainInstance } from "./index.js";

function offlinePatch() {
    log("Disabling leaderboard and unlocking all game modes...");

    const Leaderboard = Java.use("com.tann.dice.gameplay.leaderboard.Leaderboard");
    const Settings = Java.use("com.tann.dice.gameplay.save.settings.Settings");

    log("Leaderboard class: com.tann.dice.gameplay.leaderboard.Leaderboard");

    const leaderboardSig = [
        'java.lang.String',
        'com.badlogic.gdx.graphics.Color',
        'java.lang.String',
        'java.lang.String',
        'int',
        'boolean'
    ];

    overrideConstructor(Leaderboard, leaderboardSig, function (ctor, str, color, str2, str3, i, z) {
        log(`Leaderboard created: name=${str}, color=${color}, url=${str2}, scoreName=${str3}, requiredScore=${i}, keepHighest=${z}`);
        return ctor.call(this, str, color, str2, str3, i, z);
    });

    Leaderboard.makeGetRequest.implementation = function () {
        log("Leaderboard.makeGetRequest called");
        return;
    };

    Leaderboard.postScore.implementation = function () {
        log("Leaderboard.postScore called");
        return;
    };

    log("Successfully hooked Leaderboard")

    overrideMethod(Settings, "isPurchased", [], function () {
        log("Settings.isPurchased called, returning true to unlock all modes");
        return true;
    });
}

function setupGameplayHooks() {
    const TitleScreen = Java.use("com.tann.dice.screens.titleScreen.TitleScreen");

    // FIXME: Hook game start, this isn't it
    overrideConstructor(TitleScreen, [], function (ctor) {
        const instance = ctor.call(this);
        TitleScreen.selectMode.overload('com.tann.dice.gameplay.mode.Mode').implementation = function () {
            log("Dungeon is starting...")
            showPopup("pet me uwu");
            return this.selectMode();
        };
        return instance;
    });

    const Phase = Java.use("com.tann.dice.gameplay.phase.Phase");
    log("Setting up gameplay hooks...")
    overrideMethod(Phase, "actuallyDeserialise", ['java.lang.String', 'boolean'], function (method, str, z) {
        const result = method.call(this, str, z);
        log(`Deserialized phase object: ${result.toString()}`);
        return result;
    });
}

function setupMiscHooks() {
    const SplashDraw = Java.use("com.tann.dice.screens.splashScreen.SplashDraw");

    // Skip splash screen
    overrideMethod(SplashDraw, "draw", ['com.tann.dice.screens.splashScreen.SplashDraw$SplashType'], function (method, type) {
        if (type == "Loading") return;
        return method.call(this, type);
    });
}

function setupLoggingHook() {
    const TannLog = Java.use("com.tann.dice.util.TannLog");

    overrideMethod(TannLog, "log", ['java.lang.String'], function (_, message) {
        log(`[TANN] ${message}`);
    });

    overrideMethod(TannLog, "error", ['java.lang.String'], function (_, message) {
        log(`[ERR] ${message}`);
    });
}

function setupGraphDrawingHooks() {
    const GraphUtils = Java.use("com.tann.dice.screens.graph.GraphUtils");

    overrideMethod(GraphUtils, "make", [
        'java.util.List', 'int', 'boolean', 'boolean', 'com.tann.dice.screens.graph.GraphUpdate'
    ], function (method, ...args) {
        return method.call(this, ...args);
    });
}


// Draws a popup at the center of the screen
function showPopup(str) {
    mainInstance.getCurrentScreen().showDialog(str);
}

// TODO: what a mess
function drawTextBox(str, x, y) {
    // const TextBox = Java.use("com.tann.dice.util.ui.TextBox");
    // const FontWrapper = Java.use("com.tann.dice.util.FontWrapper");
    // const main = mainInstance.self();
    // const font = FontWrapper.getTannFont();

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

export {
    showPopup,
    setupGameplayHooks,
    setupLoggingHook,
    setupMiscHooks,
    setupGraphDrawingHooks,
    offlinePatch,
    drawTextBox
};

