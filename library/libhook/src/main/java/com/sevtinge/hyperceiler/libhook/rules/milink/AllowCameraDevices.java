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
package com.sevtinge.hyperceiler.libhook.rules.milink;

import android.content.Context;

import com.sevtinge.hyperceiler.common.log.XposedLog;
import com.sevtinge.hyperceiler.libhook.base.BaseHook;

import java.util.List;

import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam;
import io.github.lingqiqi5211.ezhooktool.xposed.java.IMethodHook;

public class AllowCameraDevices extends BaseHook {
    private static final String RULES_CONFIG = "com.xiaomi.vtcamera.cloud.RulesConfig";

    @Override
    public void init() {
        IMethodHook hook = new IMethodHook() {
            @Override
            public void before(HookParam param) {
                param.setResult(true);
            }
        };

        // OS2/OS3 的三代入口，保持原有顺序与语义
        try {
            findAndHookMethod(RULES_CONFIG, "isDeviceInAllowList", Context.class, String.class, hook);
        } catch (Throwable t) {
            try {
                findAndHookMethod(RULES_CONFIG, "isDeviceAllowedToBeDiscoverable", Context.class, String.class, String.class, hook);
            } catch (Throwable ignore) {
                try {
                    findAndHookMethod(RULES_CONFIG, "isDeviceAllowed", String.class, hook);
                } catch (Throwable ignored) {
                    hookOs4RulesConfig(hook);
                }
            }
        }
    }

    /**
     * OS4 入口：RulesConfig 重写为「包策略 + 规则表」模型，设备是否允许被别的设备发现
     * 统一走 {@code isAuthorised(cameraId, apiVersion, packageName, signatures,
     * activityName, targetSdkVersion, versionCode, versionName): boolean}。
     * <p>
     * 三参重载内部就是转调这个 8 参重载，所以只挂 8 参这一个即可覆盖两条路径。
     */
    private void hookOs4RulesConfig(IMethodHook hook) {
        Class<?> clazz = findClassIfExists(RULES_CONFIG);
        if (clazz == null) {
            XposedLog.e(TAG, getPackageName(), "AllowCameraDevices: RulesConfig not found in " + getPackageName());
            return;
        }
        try {
            findAndHookMethod(clazz, "isAuthorised",
                String.class, int.class, String.class, List.class,
                String.class, int.class, long.class, String.class, hook);
            XposedLog.d(TAG, getPackageName(), "AllowCameraDevices: hooked RulesConfig#isAuthorised(8 args)");
        } catch (Throwable t) {
            XposedLog.e(TAG, getPackageName(), "AllowCameraDevices: RulesConfig#isAuthorised not hookable", t);
        }
    }
}
