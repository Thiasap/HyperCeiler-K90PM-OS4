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
package com.sevtinge.hyperceiler.libhook.rules.guardprovider;

import com.sevtinge.hyperceiler.common.log.XposedLog;
import com.sevtinge.hyperceiler.libhook.base.BaseHook;
import com.sevtinge.hyperceiler.libhook.utils.hookapi.dexkit.IDexKit;
import io.github.lingqiqi5211.ezhooktool.xposed.java.IReplaceHook;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.result.MethodData;
import org.luckypray.dexkit.result.base.BaseData;

import java.lang.reflect.Method;

import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam;

public class DisableUploadAppListNew extends BaseHook {
    private Method mAntiDefraudAppManagerMethod;
    private Method mUpdateAllDetectAppsMethod;

    @Override
    protected boolean useDexKit() {
        return true;
    }

    /**
     * HyperOS 4（guardprovider 15.x）把「上传应用列表」拆成了三个方法，旧查询必然 0 命中：
     * - ie2#d(GuardApplication)：遍历 getInstalledPackages，把非系统应用的
     * 包名/版本/MD5 签名/应用名收成 ArrayList；
     * - ie2#a(ArrayList)：拼成 {"biz_id":"virus_scan", "content":[...]} 的 JSON；
     * - ls1#d(GuardApplication, JSONObject)：POST 到 https://flash.sec.miui.com/detect/app。
     * 旧查询要求「AntiDefraudAppManager」和上传 URL 出现在同一个方法里，而 URL 现在只在
     * ls1#d 里、类名字符串只在 ie2 里（ie2#a 只是调用者），所以单方法匹配不到。
     * <p>
     * 入口取 ie2#e(Context)：它就是 updateAllDetectApps，依次调 d() → a() → 落缓存，
     * MiEngineNG#g、DeviceStateReporter、Binder onTransact 三条路径都走它；
     * 用它的唯一日志字符串 "updateAllDetectApps error, " 锚定，不写死混淆类名 ie2。
     * 把 e() 整个置空，等于「从来没上传过应用列表」，缓存也不会被云端结果覆盖。
     */
    @Override
    protected boolean initDexKit() {
        mAntiDefraudAppManagerMethod = optionalMember("AntiDefraudAppManager", new IDexKit() {
            @Override
            public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                MethodData methodData = bridge.findMethod(FindMethod.create()
                        .matcher(MethodMatcher.create()
                            .usingStrings("AntiDefraudAppManager", "https://flash.sec.miui.com/detect/app")
                        ))
                    .singleOrNull();
                return methodData;
            }
        });
        if (mAntiDefraudAppManagerMethod == null) {
            mUpdateAllDetectAppsMethod = optionalMember("UpdateAllDetectAppsOs4", new IDexKit() {
                @Override
                public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                    MethodData methodData = bridge.findMethod(FindMethod.create()
                            .matcher(MethodMatcher.create()
                                .usingEqStrings("updateAllDetectApps error, ")
                                .paramTypes(android.content.Context.class)
                                .returnType(void.class)))
                        .singleOrNull();
                    return methodData;
                }
            });
        }
        return true;
    }

    @Override
    public void init() {
        if (mAntiDefraudAppManagerMethod != null) {
            XposedLog.d(TAG, getPackageName(), "Current hooking method is " + mAntiDefraudAppManagerMethod);
            hookMethod(mAntiDefraudAppManagerMethod, new IReplaceHook() {
                @Override
                public Object replace(HookParam param) {
                    return null;
                }
            });
        }
        if (mUpdateAllDetectAppsMethod != null) {
            XposedLog.d(TAG, getPackageName(), "Current hooking OS4 method is " + mUpdateAllDetectAppsMethod);
            hookMethod(mUpdateAllDetectAppsMethod, new IReplaceHook() {
                @Override
                public Object replace(HookParam param) {
                    // void 方法，直接返回 null 即整段跳过（不上传、不写缓存）
                    return null;
                }
            });
        }
        // 新旧入口都没拿到必须报 E：不允许静默跳过
        if (mAntiDefraudAppManagerMethod == null && mUpdateAllDetectAppsMethod == null) {
            XposedLog.e(TAG, getPackageName(),
                "DisableUploadAppListNew: 新旧入口均未匹配（AntiDefraudAppManager / updateAllDetectApps），应用列表仍会上传");
        }
    }
}
