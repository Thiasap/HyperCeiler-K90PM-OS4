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
import com.sevtinge.hyperceiler.libhook.utils.hookapi.dexkit.IDexKitList;
import io.github.lingqiqi5211.ezhooktool.xposed.java.IMethodHook;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.result.BaseDataList;
import org.luckypray.dexkit.result.MethodData;
import org.luckypray.dexkit.result.base.BaseData;

import java.lang.reflect.Method;
import java.util.List;

import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam;

public class DisableRootedCheck extends BaseHook {
    private List<Method> mCheckRootMethods;
    private Method mRootManagerMethod;
    private Method mBootLockedMethod;

    @Override
    protected boolean useDexKit() {
        return true;
    }

    /**
     * HyperOS 4（guardprovider 15.x）把环境检查整段重写了：
     * - 旧版「遍历 /system/bin/su 之类的 su 路径判断是否 root」的 boolean 方法已删除，
     *   现在 dex 里只剩第三方库里各自的 <clinit>（onetrack 统计 SDK、tmsdk、mediapipe），
     *   它们返回 void，所以旧查询（usingStrings("/system/bin/") + returnType boolean）必然 0 命中；
     * - 设备状态改由 DeviceStateReporter（g#run）汇总后上报，其中真正的环境判定只剩两条：
     * 1) oe2#C(GuardApplication)Z：查 com.topjohnwu.magisk / me.bmax.apatch / me.weishu.kernelsu
     * 是否安装（只认 0x800000 FLAG_INSTALLED 位），命中就打 "root manager found: "；
     * 2) oe2#G()Z：读 ro.boot.vbmeta.device_state / ro.boot.verifiedbootstate /
     * ro.secureboot.lockstate，返回 BL 是否上锁，最终写进 device_state 上报的 bl_locked 字段。
     * <p>
     * 两条都用各自唯一的日志/属性字符串锚定，不写死混淆类名（oe2 是 R8 方法外提类，混淆名跨版本会漂移）。
     * 旧系统（HyperOS 2/3）的查询保留为第一优先级，只有它 0 命中时才启用 OS4 的两条查询。
     */
    @Override
    protected boolean initDexKit() {
        mCheckRootMethods = optionalMemberList("CheckRoot", new IDexKitList() {
            @Override
            public BaseDataList<?> dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                return bridge.findMethod(FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .usingStrings("/system/bin/")
                        .returnType(boolean.class)
                    ));
            }
        });
        if (mCheckRootMethods.isEmpty()) {
            mRootManagerMethod = optionalMember("CheckRootManagerOs4", new IDexKit() {
                @Override
                public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                    MethodData methodData = bridge.findMethod(FindMethod.create()
                            .matcher(MethodMatcher.create()
                                .usingEqStrings("root manager found: ")
                                .returnType(boolean.class)))
                        .singleOrNull();
                    return methodData;
                }
            });
            mBootLockedMethod = optionalMember("CheckBootLockedOs4", new IDexKit() {
                @Override
                public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                    MethodData methodData = bridge.findMethod(FindMethod.create()
                            .matcher(MethodMatcher.create()
                                .usingEqStrings("ro.boot.vbmeta.device_state")
                                .paramCount(0)
                                .returnType(boolean.class)))
                        .singleOrNull();
                    return methodData;
                }
            });
        }
        return true;
    }

    @Override
    public void init() {
        for (Method method : mCheckRootMethods) {
            XposedLog.d(TAG, getPackageName(), "Current hooking method is " + method);
            hookMethod(method, new IMethodHook() {
                @Override
                public void before(HookParam param) {
                    param.setResult(false);
                }
            });
        }
        // OS4：root 管理器官网包名检测 → 一律当作没装
        if (mRootManagerMethod != null) {
            XposedLog.d(TAG, getPackageName(), "Current hooking OS4 root manager method is " + mRootManagerMethod);
            hookMethod(mRootManagerMethod, returnConstant(false));
        }
        // OS4：BL 上锁状态 → 一律当作已上锁（未解锁），device_state 上报里不再出现异常项
        if (mBootLockedMethod != null) {
            XposedLog.d(TAG, getPackageName(), "Current hooking OS4 boot locked method is " + mBootLockedMethod);
            hookMethod(mBootLockedMethod, returnConstant(true));
        }
        // 新旧入口一个都没拿到必须报 E：说明本规则在新系统上完全失配，不允许静默跳过
        if (mCheckRootMethods.isEmpty() && mRootManagerMethod == null && mBootLockedMethod == null) {
            XposedLog.e(TAG, getPackageName(),
                "DisableRootedCheck: 新旧入口均未匹配（/system/bin/ 路径检查 / root manager 包名检查 / BL 上锁检查），环境检查未生效");
        }
    }
}
