import { log } from "./logger.js";

Java.perform(() => {
    const unutilClass = "com.tann.dice.gameplay.progress.chievo.unlock.UnUtil";
    const leaderboardClass = "com.tann.dice.gameplay.leaderboard.Leaderboard";
    const UnUtil = Java.use(unutilClass);
    const Leaderboard = Java.use(leaderboardClass);

    log("Hooking UnUtil methods...");

    const unutilInit_o = UnUtil.$init.overload();
    UnUtil.$init.overload().implementation = function () {
        log("UnUtil instance created: " + this);
        const result = unutilInit_o.call(this);
        return result;
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
});