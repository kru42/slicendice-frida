import { log } from "./logger.js";

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

function enableDebugMode() {
    // Enable debug mode
    log("Enabling debug mode...");

    const debugClass = "com.tann.dice.gameplay.mode.debuggy.DebugMode";
    const DebugMode = Java.use(debugClass);

    log(`DebugMode class: ${debugClass}`);

    const debugModeCtor = DebugMode.$init.overload();
    DebugMode.$init.overload().implementation = function () {
        log("DebugMode instance created: " + this);
        return debugModeCtor.call(this);
    }

    // Hook the DebugMode.isPlayable method to always return true
    DebugMode.isPlayable.implementation = function () {
        log("DebugMode.isPlayable called, returning true");
        return true;
    };
}

function startCustomMode() {
    const DemoMode = Java.use("com.tann.dice.gameplay.mode.general.DemoMode");
    const DebugConfig = Java.use("com.tann.dice.gameplay.context.config.misc.DebugConfig");
    const Arrays = Java.use("java.util.Arrays");
    const StandardButton = Java.use("com.tann.dice.util.ui.standardButton.StandardButton");
    const Runnable = Java.use("java.lang.Runnable");

    DebugConfig.makeStartButton.implementation = function (z) {
        log("makeStartButton() hooked for DebugConfig");
        const btn = StandardButton.$new.overload('java.lang.String').call(StandardButton, "[green]Start thing lol");

        const MyRunnable = Java.registerClass({
            name: "com.example.MyRunnable",
            implements: [Runnable],
            methods: {
                run: function () {
                    log("Debug start button pressed (noop)");
                }
            }
        });

        btn.setRunnable(MyRunnable.$new());
        return btn;
    };

    DemoMode.makeAllConfigs.implementation = function () {
        log("Overriding DemoMode config with DebugConfig");
        const dbgConfig = DebugConfig.$new(); // Create DebugConfig instance

        // Create a Java array of ContextConfig (superclass of DebugConfig)
        const ContextConfigArray = Java.array('com.tann.dice.gameplay.context.config.ContextConfig', [dbgConfig]);
        return Arrays.asList(ContextConfigArray);
    };
}

Java.perform(() => {
    offlinePatch();
    enableDebugMode();

    startCustomMode();
});