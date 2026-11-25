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
package com.sevtinge.hyperceiler.libhook.rules.powerkeeper;

import com.sevtinge.hyperceiler.common.log.XposedLog;
import com.sevtinge.hyperceiler.libhook.base.BaseHook;
import com.sevtinge.hyperceiler.libhook.utils.hookapi.dexkit.IDexKit;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.result.MethodData;
import org.luckypray.dexkit.result.base.BaseData;

import java.lang.reflect.Method;

import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam;
import io.github.lingqiqi5211.ezhooktool.xposed.java.IMethodHook;

public class CustomRefreshRate extends BaseHook {
    private static final String FIELD_CUSTOM_FPS_SWITCH = "mIsCustomFpsSwitch";
    private static final String VALUE_ENABLED = "true";

    private Method mFucSwitchMethod;
    private Method mParseCustomModeSwitchMethod;

    @Override
    protected boolean useDexKit() {
        return true;
    }

    /**
     * HyperOS 4（PowerKeeper）里 "custom_mode_switch" 与 "fucSwitch" 只剩
     * {@code DisplayFrameSetting#parseCustomModeSwitchFromDb(String)V} 一个方法使用，
     * 它返回 void，所以旧查询（两个字符串 + returnType(boolean)）必然 0 命中，
     * 规则在 initDexKit 阶段就抛错、hook 一个都装不上。
     * <p>
     * 该方法就是把云端/本地配置里的 fucSwitch 解析进静态字段
     * {@code DisplayFrameSetting.mIsCustomFpsSwitch}（String，"true" 表示开启自定义帧率）。
     * 因此 OS4 兜底改为 hook 它，并在 after 里把字段强制写成 "true"
     * —— 必须放在 after：原方法体本身就会写这个字段，写在 before 会被覆盖。
     * <p>
     * OS4 的目标方法先用「类名 + 方法名 + String 单参 + void」这个结构不变量定位
     * （上游 93817d8f6 的改法，三版反汇编里该方法未混淆且唯一）；
     * 万一以后改名，再退回「两串 AND + String 单参 + void」；
     * 两条都没命中才回退旧系统的 fucSwitch 查询；全部失配时打 E。
     */
    @Override
    protected boolean initDexKit() {
        // ① 新逻辑优先：结构不变量定位 OS4 的 parseCustomModeSwitchFromDb(String)
        mParseCustomModeSwitchMethod = optionalMember("ParseCustomModeSwitchOs4", new IDexKit() {
            @Override
            public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                MethodData methodData = bridge.findMethod(FindMethod.create()
                        .matcher(MethodMatcher.create()
                            .declaredClass("com.miui.powerkeeper.statemachine.DisplayFrameSetting")
                            .name("parseCustomModeSwitchFromDb")
                            .paramTypes("java.lang.String")
                            .returnType(void.class)
                        )).singleOrNull();
                return methodData;
            }
        });
        // ② 方法改名时退回字符串锚点（语义与 ① 相同）
        if (mParseCustomModeSwitchMethod == null) {
            mParseCustomModeSwitchMethod = optionalMember("ParseCustomModeSwitchByString", new IDexKit() {
                @Override
                public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                    MethodData methodData = bridge.findMethod(FindMethod.create()
                            .matcher(MethodMatcher.create()
                                .usingEqStrings("custom_mode_switch", "fucSwitch")
                                .paramTypes(String.class)
                                .returnType(void.class)
                            )).singleOrNull();
                    return methodData;
                }
            });
        }
        // ③ 新锚点全部未命中才回退旧逻辑
        if (mParseCustomModeSwitchMethod == null) {
            mFucSwitchMethod = optionalMember("FucSwitch", new IDexKit() {
                @Override
                public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                    MethodData methodData = bridge.findMethod(FindMethod.create()
                            .matcher(MethodMatcher.create()
                                    .usingStrings("custom_mode_switch", "fucSwitch")
                                    .returnType(boolean.class)
                            )).singleOrNull();
                    return methodData;
                }
            });
        }
        return true;
    }

    @Override
    public void init() {
        // 新逻辑优先：OS4 在 after 里把静态字段强制写成 "true"
        if (mParseCustomModeSwitchMethod != null) {
            XposedLog.d(TAG, getPackageName(), "Current hooking OS4 method is " + mParseCustomModeSwitchMethod);
            final Class<?> os4Owner = mParseCustomModeSwitchMethod.getDeclaringClass();
            hookMethod(mParseCustomModeSwitchMethod, new IMethodHook() {
                @Override
                public void after(HookParam param) {
                    // mIsCustomFpsSwitch 是 static String，必须走静态写入；
                    // 上游用 setObjectField(param.getThisObject(), ...) 在 before 里预置，
                    // 但本机实测实例写入会抛 NoSuchFieldException，且 before 里写的值会被原方法体覆盖。
                    setStaticObjectField(os4Owner, FIELD_CUSTOM_FPS_SWITCH, VALUE_ENABLED);
                    XposedLog.d(TAG, getPackageName(),
                        "mIsCustomFpsSwitch forced to \"" + VALUE_ENABLED + "\" after parseCustomModeSwitchFromDb");
                }
            });
        }
        // 旧逻辑兜底：老系统的 fucSwitch 开关方法（字段同样是 static）
        if (mFucSwitchMethod != null) {
            XposedLog.d(TAG, getPackageName(), "Current hooking method is " + mFucSwitchMethod);
            final Class<?> legacyOwner = mFucSwitchMethod.getDeclaringClass();
            hookMethod(mFucSwitchMethod, new IMethodHook() {
                @Override
                public void before(HookParam param) {
                    setStaticObjectField(legacyOwner, FIELD_CUSTOM_FPS_SWITCH, VALUE_ENABLED);
                }
            });
        }
        // 新旧入口都没拿到必须报 E：自定义帧率开关没有被强制打开
        if (mFucSwitchMethod == null && mParseCustomModeSwitchMethod == null) {
            XposedLog.e(TAG, getPackageName(),
                "CustomRefreshRate: 新旧入口均未匹配（fucSwitch 开关 / parseCustomModeSwitchFromDb），自定义刷新率未生效");
        }
    }
}
