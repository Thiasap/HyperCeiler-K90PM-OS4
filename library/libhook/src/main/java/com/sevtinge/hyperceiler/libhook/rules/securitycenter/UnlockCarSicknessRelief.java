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
package com.sevtinge.hyperceiler.libhook.rules.securitycenter;

import android.content.Context;

import com.sevtinge.hyperceiler.libhook.base.BaseHook;
import com.sevtinge.hyperceiler.libhook.utils.hookapi.dexkit.IDexKit;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.result.MethodData;
import org.luckypray.dexkit.result.base.BaseData;

import java.lang.reflect.Method;

public class UnlockCarSicknessRelief extends BaseHook {
    private Method mUnlockCarSicknessReliefMethod;
    private Method mUnlockCarSicknessRemindTimingMethod;

    @Override
    protected boolean useDexKit() {
        return true;
    }

    @Override
    protected boolean initDexKit() {
        // OS4 的防晕车设置被重写（安全中心里只剩 com.miui.carsickness.*），
        // 原来用 "is_support_carsick" 定的类已经不存在，这里改成「可选匹配」：
        // 命中就照旧 hook，没命中就跳过，不再让整条规则以 initDexKit failed 报错退出。
        mUnlockCarSicknessReliefMethod = optionalMember("UnlockCarSicknessRelief", new IDexKit() {
            @Override
            public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                MethodData methodData = bridge.findMethod(FindMethod.create()
                        .matcher(MethodMatcher.create()
                            .usingStrings("is_support_carsick")
                            .returnType(boolean.class)
                            .paramTypes(Context.class)))
                    .singleOrNull();
                return methodData;
            }
        });
        mUnlockCarSicknessRemindTimingMethod = optionalMember("UnlockCarSicknessRemindTiming", new IDexKit() {
            @Override
            public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                MethodData methodData = bridge.findMethod(FindMethod.create()
                        .matcher(MethodMatcher.create()
                            .addCaller(MethodMatcher.create()
                                .declaredClass(findClassIfExists("com.miui.carsickness.ui.CarSicknessReliefSettingsActivity$MotionSicknessReliefSettingsFragment"))
                                .name("onCreatePreferences"))
                            .returnType(boolean.class)
                            .paramTypes(Context.class)))
                    .singleOrNull();
                return methodData;
            }
        });
        return true;
    }

    @Override
    public void init() {
        if (mUnlockCarSicknessReliefMethod != null) {
            hookMethod(mUnlockCarSicknessReliefMethod, returnConstant(true));
        }
        if (mUnlockCarSicknessRemindTimingMethod != null) {
            hookMethod(mUnlockCarSicknessRemindTimingMethod, returnConstant(true));
        }
    }
}

