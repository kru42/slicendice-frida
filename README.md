## slicendice-frida
1. su location on bluestacks: `/boot/android/android/system/xbin/bstk/su`
2. place frida-server in `/data/local/tmp` dir and run it (v16, 17 was a mess to configure)
3. attach with `frida -U -p <pid> -l ./_agent.js`, or spawn com.com.tann.dice (not sure why the actual package name is com.com)
4. `adb shell am clear-debug-app` to unfuck adb - https://stackoverflow.com/a/56541740

NOTE: I can't configure typescript lol