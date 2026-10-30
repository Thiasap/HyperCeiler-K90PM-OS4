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

import com.sevtinge.hyperceiler.common.log.XposedLog;
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
    private Method mCarSicknessSupportMethod;
    private Method mCarSicknessSupportEntryMethod;

    @Override
    protected boolean useDexKit() {
        return true;
    }

    /**
     * OS4（安全中心 8.x）把防晕车重写进 com.miui.carsickness.*：
     * - "is_support_carsick" 字符串已删除，旧查询 0 命中；
     * - 「本机是否支持」变成 s6.b#h(Context)Z：设备白名单(d()) 或 FeatureParser
     *   support_travel_comfort_solution(e()) 之一成立，且加速度/重力传感器齐全；
     *   设置页 onCreatePreferences 里 b.i(context) 为 false 时会把「提醒时机」下拉直接移除，
     *   b.h 则控制入口是否可用（l() 写入 Settings.Secure car_sickness_is_support）。
     * - 白名单名单写死在 s6.b 的静态 List（f42422a），K90 Pro Max 不在里面，
     *   所以把 h() / i() 强制 true 即可在本机解锁完整设置。
     * 查询用 addInvoke 精确锚定 Ls6/b;->i(...)Z 的唯一调用点（设置页 onCreatePreferences），
     * 避免按混淆类名 s6.b 硬匹配（混淆名跨版本会漂移）。
     * 兼容旧系统：旧键 is_support_carsick 的查询保留为第一优先级。
     */
    @Override
    protected boolean initDexKit() {
        // 旧系统入口：HyperOS 2/3 用 "is_support_carsick" 定位，保留第一优先级。
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
        // OS4 入口：两个查询都失配时，按新实现重新定位（防止上面的 optional 匹配把失配掩盖掉）。
        if (mUnlockCarSicknessReliefMethod == null && mUnlockCarSicknessRemindTimingMethod == null) {
            mCarSicknessSupportMethod = optionalMember("CarSicknessSupportOs4", new IDexKit() {
                @Override
                public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                    MethodData methodData = bridge.findMethod(FindMethod.create()
                            .matcher(MethodMatcher.create()
                                .addInvoke("Ls6/b;->h(Landroid/content/Context;)Z")))
                        .singleOrNull();
                    return methodData;
                }
            });
            mCarSicknessSupportEntryMethod = optionalMember("CarSicknessSupportEntryOs4", new IDexKit() {
                @Override
                public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                    MethodData methodData = bridge.findMethod(FindMethod.create()
                            .matcher(MethodMatcher.create()
                                .addInvoke("Ls6/b;->i(Landroid/content/Context;)Z")))
                        .singleOrNull();
                    return methodData;
                }
            });
        }
        return true;
    }

    @Override
    public void init() {
        // 旧系统入口照旧
        if (mUnlockCarSicknessReliefMethod != null) {
            hookMethod(mUnlockCarSicknessReliefMethod, returnConstant(true));
        }
        if (mUnlockCarSicknessRemindTimingMethod != null) {
            hookMethod(mUnlockCarSicknessRemindTimingMethod, returnConstant(true));
        }
        // OS4 入口：支持性判定强制 true，让设置页与入口完整可用
        if (mCarSicknessSupportMethod != null) {
            hookMethod(mCarSicknessSupportMethod, returnConstant(true));
        }
        if (mCarSicknessSupportEntryMethod != null) {
            hookMethod(mCarSicknessSupportEntryMethod, returnConstant(true));
        }
        // 新旧入口一个都没拿到时必须报 E：说明规则在新系统上完全失配，不允许静默跳过
        if (mUnlockCarSicknessReliefMethod == null
                && mUnlockCarSicknessRemindTimingMethod == null
                && mCarSicknessSupportMethod == null
                && mCarSicknessSupportEntryMethod == null) {
            XposedLog.e(TAG, getPackageName(),
                "UnlockCarSicknessRelief: 新旧入口均未匹配（is_support_carsick / s6.b#h / s6.b#i），防晕车解锁未生效");
        }
    }
}

