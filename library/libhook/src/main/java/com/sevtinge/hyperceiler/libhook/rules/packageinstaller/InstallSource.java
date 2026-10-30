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
package com.sevtinge.hyperceiler.libhook.rules.packageinstaller;

import android.app.Activity;

import com.sevtinge.hyperceiler.common.log.XposedLog;
import com.sevtinge.hyperceiler.common.utils.PrefsBridge;
import com.sevtinge.hyperceiler.libhook.base.BaseHook;
import io.github.lingqiqi5211.ezhooktool.xposed.java.IMethodHook;

import java.lang.reflect.Method;

import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam;

public class InstallSource extends BaseHook {

    String mInstallSourcePackageName;

    /**
     * 伪装后的安装来源 uid，-1 表示尚未解析/解析失败。
     */
    int mInstallSourceUid = -1;

    @Override
    public void init() {

        mInstallSourcePackageName = PrefsBridge.getString("miui_package_installer_install_source", "com.android.fileexplorer");

        findAndHookMethod(Activity.class, "getLaunchedFromPackage", new IMethodHook(){
            @Override
            public void before(HookParam param) {
                if (isCalledFromInstallStart()) param.setResult(mInstallSourcePackageName);
            }
        });

        findAndHookMethod("com.miui.packageInstaller.InstallStart",
            "getCallingPackage",
            returnConstant(mInstallSourcePackageName));

        hookInstallSourceUid();
    }

    /**
     * OS4 起，安装器会用 (getLaunchedFromUid(), getCallingPackage()) 去查 AppOps 的
     * 「android:request_install_packages」：只把包名伪装成文件管理、uid 还是真实调用者时，
     * AppOpsService 会直接抛 SecurityException
     * （Bad call made by uid A. Package "com.android.fileexplorer" does not belong to uid B），
     * 安装器把这个异常当成「不允许安装」，于是弹出「是否允许「文件管理」安装应用？」。
     * 所以 uid 必须和包名一起伪装，让 (uid, 包名) 重新变成合法组合。
     */
    private void hookInstallSourceUid() {
        Method getLaunchedFromUid = findMethodExactIfExists(Activity.class, "getLaunchedFromUid");
        if (getLaunchedFromUid == null) {
            XposedLog.e(TAG, getPackageName(), "Activity#getLaunchedFromUid 不存在，安装来源 uid 无法伪装");
            return;
        }
        hookMethod(getLaunchedFromUid, new IMethodHook(){
            @Override
            public void before(HookParam param) {
                if (!isCalledFromInstallStart()) return;
                int uid = resolveInstallSourceUid(param.getThisObject());
                if (uid > 0) param.setResult(uid);
            }
        });
    }

    private int resolveInstallSourceUid(Object activity) {
        if (mInstallSourceUid > 0) return mInstallSourceUid;
        if (!(activity instanceof Activity)) return -1;
        try {
            int uid = ((Activity) activity).getPackageManager()
                .getPackageUid(mInstallSourcePackageName, 0);
            if (uid <= 0) {
                XposedLog.e(TAG, getPackageName(),
                    "安装来源包不存在，无法伪装 uid：" + mInstallSourcePackageName);
                return -1;
            }
            mInstallSourceUid = uid;
            XposedLog.d(TAG, getPackageName(),
                "安装来源伪装为 " + mInstallSourcePackageName + " (uid " + uid + ")");
            return uid;
        } catch (Throwable t) {
            XposedLog.e(TAG, getPackageName(),
                "获取安装来源 uid 失败：" + mInstallSourcePackageName, t);
            return -1;
        }
    }

    private boolean isCalledFromInstallStart() {
        try {
            StackTraceElement[] st = Thread.currentThread().getStackTrace();
            if (st == null) return false;

            for (int i = 0; i < st.length - 1; i++) {
                StackTraceElement cur = st[i];
                StackTraceElement next = st[i + 1];

                if (cur == null || next == null) continue;

                if (cur.getClassName() != null
                    && cur.getClassName().startsWith("com.miui.packageInstaller")) {

                    if ("com.miui.packageInstaller.InstallStart".equals(next.getClassName())
                        && "onCreate".equals(next.getMethodName())) {
                        return true;
                    }
                }
            }
        } catch (Throwable t) {
            XposedLog.e(TAG, "isCalledFromInstallStartStrict error: " + t);
        }
        return false;
    }

}
