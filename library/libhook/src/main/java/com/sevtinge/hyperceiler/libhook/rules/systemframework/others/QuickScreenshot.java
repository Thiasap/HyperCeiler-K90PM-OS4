/*
  * This file is part of HyperCeiler.

  * HyperCeiler is free software: you can redistribute it and/or modify
  * it under the terms of the GNU Affero General Public License as
  * published by the Free Software Foundation, either version 3 of the
  * License.

  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU Affero General Public License for more details.

  * You should have received a copy of the GNU Affero General Public License
  * along with this program.  If not, see <https://www.gnu.org/licenses/>.

  * Copyright (C) 2023-2026 HyperCeiler Contributions
*/
package com.sevtinge.hyperceiler.libhook.rules.systemframework.others;

import com.sevtinge.hyperceiler.common.log.XposedLog;
import com.sevtinge.hyperceiler.libhook.base.BaseHook;
import io.github.lingqiqi5211.ezhooktool.xposed.java.IMethodHook;

import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam;

public class QuickScreenshot extends BaseHook {
    private static final String METHOD = "getScreenshotChordLongPressDelay";

    /**
     * 旧实现所在类：Android 6 ~ HyperOS 3 一直由 PhoneWindowManager 持有。
     * 该 hook 在 OS4 上会抛 "Method not found"，因此保留原逻辑不动，只在外层兜底。
     */
    private static final String LEGACY_CLASS = "com.android.server.policy.PhoneWindowManager";

    /**
     * OS4（Android 17）把截屏按键手势整体搬进了 KeyGestureController，
     * 方法签名与语义保持不变：{@code public long getScreenshotChordLongPressDelay()}。
     */
    private static final String OS4_CLASS = "com.android.server.input.KeyGestureController";

    @Override
    public void init() {
        IMethodHook zeroDelay = new IMethodHook() {
            @Override
            public void before(HookParam param) {
                param.setResult(0L);
            }
        };

        if (hookChordDelay(LEGACY_CLASS, zeroDelay)) return;
        if (hookChordDelay(OS4_CLASS, zeroDelay)) return;

        XposedLog.e(TAG, getPackageName(),
            "QuickScreenshot: " + METHOD + " not found in " + LEGACY_CLASS + " nor " + OS4_CLASS);
    }

    /**
     * 尝试在指定类上挂载截屏长按时长 hook。
     * 类不存在时 findAndHookMethod 只返回 null（自身会打 W 日志）；
     * 方法不存在时 ezhooktool 会抛异常，这里必须吞掉，否则会中断 BaseHook.init 并让整个规则失效。
     */
    private boolean hookChordDelay(String className, IMethodHook hook) {
        try {
            if (findAndHookMethod(className, METHOD, hook) == null) return false;
            XposedLog.d(TAG, getPackageName(), "QuickScreenshot: hooked " + className + "#" + METHOD);
            return true;
        } catch (Throwable t) {
            XposedLog.w(TAG, getPackageName(),
                "QuickScreenshot: " + className + "#" + METHOD + " not hookable, trying next", t);
            return false;
        }
    }
}
