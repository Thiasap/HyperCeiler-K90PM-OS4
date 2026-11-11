package com.sevtinge.hyperceiler.libhook.rules.systemui.navigation;

import android.content.SharedPreferences;
import android.content.Context;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicLong;
import android.os.Handler;
import android.os.Looper;
import com.sevtinge.hyperceiler.common.log.XposedLog;
import com.sevtinge.hyperceiler.common.utils.PrefsBridge;
import com.sevtinge.hyperceiler.libhook.base.BaseHook;
import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam;
import io.github.lingqiqi5211.ezhooktool.xposed.java.IMethodHook;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.WeakHashMap;

/** SystemUI rejects downs beyond its resource edge even when Home's native window accepts them. */
public final class BackGestureWidthOS4 extends BaseHook {
    private final Map<Object, BackGestureWidthState> states = new WeakHashMap<>();
    private Field left, right;
    private volatile int percent = 100;
    private volatile boolean closed;
    private Context context;
    private final AtomicLong request = new AtomicLong();
    private final Handler main = new Handler(Looper.getMainLooper());
    @Override public void init() {
        Class<?> type = findClassIfExists("com.android.systemui.navigationbar.gestural.EdgeBackGestureHandler");
        if (type == null) return;
        final Method resources;
        try {
            left = type.getDeclaredField("mEdgeWidthLeft");
            right = type.getDeclaredField("mEdgeWidthRight");
            resources = type.getDeclaredMethod("updateCurrentUserResources");
            if (left.getType() != int.class || right.getType() != int.class
                || resources.getReturnType() != void.class) return;
            left.setAccessible(true); right.setAccessible(true);
        } catch (ReflectiveOperationException error) {
            XposedLog.w(TAG, "edge resource shape not validated: " + error); return;
        }
        percent = readPercent();
        hookMethod(resources, new IMethodHook() {
            @Override public void after(HookParam p) { refresh(p.getThisObject(), true); }
        });
        hookAllConstructors(type, new IMethodHook() {
            @Override public void after(HookParam p) { refresh(p.getThisObject(), false); }
        });
        SharedPreferences prefs = PrefsBridge.getSharedPreferences();
        if (prefs != null) {
            SharedPreferences.OnSharedPreferenceChangeListener listener = (p, key) -> {
                if (key == null || key.equals("home_navigation_back_area_width")
                    || key.equals("prefs_key_home_navigation_back_area_width")) {
                    main.post(() -> { if (closed) return; refreshFromPrefs(); });
                }
            };
            prefs.registerOnSharedPreferenceChangeListener(listener);
            registerHotReloadCleanup(() -> { closed = true; prefs.unregisterOnSharedPreferenceChangeListener(listener); });
        }
        runOnApplicationAttach(c -> attach(c));
        registerHotReloadCleanup(() -> { closed = true; request.incrementAndGet(); restoreAll(); });
        XposedLog.i(TAG, "validated original edge widths consumer; initial=" + percent);
    }
    private void attach(Context c) {
        if (closed || context != null) return;
        context = c.getApplicationContext();
        if (context == null) context = c;
        // No provider observer here. A ContentObserver on the module provider keeps a live
        // connection from SystemUI, and the platform re-acquires it after every restart - which
        // is exactly what turns a provider-only cold start into a kill/restart cycle. The remote
        // preferences listener registered in init() already reports every change.
        refreshFromPrefs();
    }
    // Remote preferences are already in this process: the value is read locally instead of
    // querying the module provider, which is a cross-process call into an app the platform
    // freezes within seconds.
    private void refreshFromPrefs() {
        if (closed) return;
        long version = request.incrementAndGet();
        int value = readPercent();
        main.post(() -> {
            if (closed || request.get() != version) return;
            percent = value; refreshAll();
        });
    }
    private int readPercent() {
        try { return BackGestureWidthState.normalize(PrefsBridge.getInt("home_navigation_back_area_width", 100)); }
        catch (Throwable ignored) { return 100; }
    }
    private synchronized void refresh(Object target, boolean resourceReset) {
        if (closed || target == null) return;
        try {
            int l = left.getInt(target), r = right.getInt(target);
            BackGestureWidthState state = states.get(target);
            if (state == null) { state = new BackGestureWidthState(l, r); states.put(target, state); }
            else if (resourceReset) state.reset(l, r);
            state.apply(percent);
            left.setInt(target, state.appliedLeft); right.setInt(target, state.appliedRight);
        } catch (ReflectiveOperationException error) { XposedLog.w(TAG, "edge fields retained: " + error); }
    }
    private synchronized void refreshAll() { for (Object target : new ArrayList<>(states.keySet())) refresh(target, false); }
    private synchronized void restoreAll() {
        for (Map.Entry<Object, BackGestureWidthState> e : states.entrySet()) {
            try {
                BackGestureWidthState s = e.getValue();
                // Do not overwrite a later resource/other module change on cleanup.
                if (left.getInt(e.getKey()) == s.appliedLeft) left.setInt(e.getKey(), s.left);
                if (right.getInt(e.getKey()) == s.appliedRight) right.setInt(e.getKey(), s.right);
            } catch (ReflectiveOperationException ignored) { }
        }
        states.clear();
    }
}
