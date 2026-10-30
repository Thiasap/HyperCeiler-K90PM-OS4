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
 *
 * Copyright (C) 2023-2026 HyperCeiler Contributions
 */

package com.sevtinge.hyperceiler.libhook.rules.fileexplorer;

import com.sevtinge.hyperceiler.common.log.XposedLog;
import com.sevtinge.hyperceiler.libhook.base.BaseHook;
import io.github.lingqiqi5211.ezhooktool.xposed.java.IMethodHook;

import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam;

public class UnlockFileParse extends BaseHook {
    /**
     * 旧入口：HyperOS 2/3 一直由 RomUtils 提供全局「文件解析」开关。
     * OS4 上整个 APK 已不存在 supportFileParse，保留它是为了兼容其它机型/旧系统。
     */
    private static final String LEGACY_CLASS = "com.android.fileexplorer.util.RomUtils";
    private static final String LEGACY_METHOD = "supportFileParse";

    /**
     * OS4 入口：文件解析被重构成独立的 fileparse 模块，
     * 全局开关变成 IFileParseUtils#isSupportFileParse()Z（静态方法）。
     */
    private static final String OS4_CLASS = "com.android.fileexplorer.fileparse.util.IFileParseUtils";
    private static final String OS4_METHOD = "isSupportFileParse";

    @Override
    public void init() {
        IMethodHook supported = new IMethodHook() {
            @Override
            public void before(HookParam param) {
                param.setResult(true);
            }
        };

        if (hookFileParse(LEGACY_CLASS, LEGACY_METHOD, supported)) return;
        if (hookFileParse(OS4_CLASS, OS4_METHOD, supported)) return;

        XposedLog.e(TAG, getPackageName(),
            "UnlockFileParse: no file parse switch found (" + LEGACY_CLASS + "#" + LEGACY_METHOD
                + " / " + OS4_CLASS + "#" + OS4_METHOD + ")");
    }

    private boolean hookFileParse(String className, String methodName, IMethodHook hook) {
        try {
            if (findAndHookMethod(className, methodName, hook) == null) return false;
            XposedLog.d(TAG, getPackageName(), "UnlockFileParse: hooked " + className + "#" + methodName);
            return true;
        } catch (Throwable t) {
            XposedLog.w(TAG, getPackageName(),
                "UnlockFileParse: " + className + "#" + methodName + " not hookable, trying next", t);
            return false;
        }
    }
}
