/*
 * This file is part of HyperCeiler.
 *
 * HyperCeiler is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2023-2026 HyperCeiler Contributions
 */

package com.sevtinge.hyperceiler.libhook.rules.securitycenter;

import com.sevtinge.hyperceiler.common.log.XposedLog;
import com.sevtinge.hyperceiler.libhook.base.BaseHook;
import io.github.lingqiqi5211.ezhooktool.xposed.java.IMethodHook;
import com.sevtinge.hyperceiler.libhook.utils.hookapi.dexkit.IDexKit;
import com.sevtinge.hyperceiler.libhook.utils.hookapi.dexkit.IDexKitList;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindClass;
import org.luckypray.dexkit.query.FindField;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.ClassMatcher;
import org.luckypray.dexkit.query.matchers.FieldMatcher;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.result.BaseDataList;
import org.luckypray.dexkit.result.ClassData;
import org.luckypray.dexkit.result.FieldData;
import org.luckypray.dexkit.result.MethodData;
import org.luckypray.dexkit.result.MethodDataList;
import org.luckypray.dexkit.result.base.BaseData;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;

import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam;

public class DisableRootedCheck extends BaseHook {
    private Method mReturnEnvironmentMethod;
    private Class<?> mClientApiRequestClass;
    private Method mEnvironmentPutMethod;
    private Class<?> mRiskAppClass;
    private Field mRiskAppField;
    private Method mUnsetEnvironmentMethod;
    private List<Method> mSetEnvironmentMethods;
    private List<Method> mCheckRootMethods;
    private boolean mRiskAppIsGuardHandler;

    @Override
    protected boolean useDexKit() {
        return true;
    }

    @Override
    protected boolean initDexKit() {
        mReturnEnvironmentMethod = requiredMember("ReturnEnvironment", new IDexKit() {
            @Override
            public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                MethodData methodData = bridge.findMethod(FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .usingStrings("Invalid Task , reason:  [canceled, ")
                    )).singleOrNull();
                return methodData;
            }
        });
        mClientApiRequestClass = requiredMember("ClientApiRequest", new IDexKit() {
            @Override
            public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                ClassData classData = bridge.findClass(FindClass.create()
                    .matcher(ClassMatcher.create()
                        .usingStrings("ClientApiRequest")
                    )).singleOrNull();
                return classData;
            }
        });
        mEnvironmentPutMethod = requiredMember("EnvironmentPut", new IDexKit() {
            @Override
            public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                MethodData methodData = bridge.findMethod(FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .declaredClass(mClientApiRequestClass)
                        .returnType(boolean.class)
                    )).singleOrNull();
                return methodData;
            }
        });
        mRiskAppClass = requiredMember("RiskAppClass", new IDexKit() {
            @Override
            public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                ClassData classData = bridge.findClass(FindClass.create()
                    .matcher(ClassMatcher.create()
                        .usingStrings("RiskAppManager")
                    )).singleOrNull();
                return classData;
            }
        });
        mRiskAppField = requiredMember("RiskApp", new IDexKit() {
            @Override
            public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                FieldData fieldData = bridge.findField(FindField.create()
                    .matcher(FieldMatcher.create()
                        .type(mRiskAppClass)
                        .modifiers(Modifier.PRIVATE)
                    )).singleOrNull();
                return fieldData;
            }
        });
        mUnsetEnvironmentMethod = requiredMember("UnsetEnvironment", new IDexKit() {
            @Override
            public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                MethodData methodData = bridge.findMethod(FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .usingStrings("RiskAppManager")
                    )).singleOrNull();
                return methodData;
            }
        });
        mSetEnvironmentMethods = requiredMemberList("SetEnvironment", new IDexKitList() {
            @Override
            public BaseDataList<MethodData> dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                MethodDataList methodData = bridge.findMethod(FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .returnType(void.class)
                        .paramTypes(mClientApiRequestClass)
                        .declaredClass(mRiskAppClass)
                    )
                );
                return methodData;
            }
        });
        mCheckRootMethods = requiredMemberList("CheckRoot", new IDexKitList() {
            @Override
            public BaseDataList<MethodData> dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                MethodDataList methodData = bridge.findMethod(FindMethod.create()
                        .matcher(MethodMatcher.create()
                                .usingStrings("/system/bin/")
                                .returnType(boolean.class)
                        )
                );
                return methodData;
            }
        });
        // OS4 判别：上面那个「RiskAppManager 类」在 HyperOS 4 上已经不是环境设置器了，
        // 而是风险应用名单处理器 —— 它的方法直接查 content://guard（getRiskAppData）。
        // 用「该类是否直接走 content://guard」来判别，比按版本号硬卡稳。
        mRiskAppIsGuardHandler = optionalMember("RiskAppGuardProbe", new IDexKit() {
            @Override
            public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                MethodData methodData = bridge.findMethod(FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .declaredClass(mRiskAppClass)
                        .usingStrings("content://guard")
                    )).singleOrNull();
                return methodData;
            }
        }) != null;
        return true;
    }

    @Override
    public void init() {
        if (mRiskAppIsGuardHandler) {
            // HyperOS 4：go.a 只剩 (user, appId, appKey)，XSOF 请求里已经没有 environment 字段，
            // 旧的环境伪造链路没有可改写的目标；更糟的是旧代码会把「RiskAppManager」类里
            // 所有 void(ClientApiRequest) 方法当成 setEnvironment 全调一遍，而 OS4 这个类里的
            // 方法其实是风险应用处理器：eo.b#c 会去查 content://guard#getRiskAppData 并直接
            // aVar.c(riskData, 0) 回调客户端 —— 一旦被这样调用，本次 XSOF 任务的真实回复
            // 就会被顶掉（回调被置空后原流程的回复发不出去）。
            // 所以 OS4 不挂这条 hook；本机 root 检测由下面 mCheckRootMethods 那一批负责。
            XposedLog.w(TAG, getPackageName(),
                "OS4 XSOF 请求已无 environment 字段，且『环境设置目标』实为风险应用名单处理器，跳过环境伪造");
        } else {
            hookMethod(mReturnEnvironmentMethod, new IMethodHook() {
                @Override
                public void before(HookParam param) {
                    Object obj = param.getArgs()[0];
                    if (mClientApiRequestClass.isInstance(obj)) {
                        callMethod(obj, mEnvironmentPutMethod.getName());
                        Object thisObj = param.getThisObject();
                        Object cField = getObjectField(thisObj, mRiskAppField.getName());
                        for (Method method : mSetEnvironmentMethods) {
                            if (!isSameMethod(method, mUnsetEnvironmentMethod)) {
                                callMethod(cField, method.getName(), obj);
                            }
                        }
                    }
                }
            });
        }
        for (Method method : mCheckRootMethods) {
            // Method method = methodData.getMethodInstance(lpparam.classLoader);
            XposedLog.d(TAG, getPackageName(), "Current hooking method is " + method);
            hookMethod(method, new IMethodHook() {
                @Override
                public void before(HookParam param) {
                    param.setResult(false);
                }
            });
        }
    }

    /**
     * 按「方法名 + 参数类型」判断是不是同一个方法。
     * <p>
     * 原实现用 {@code method != mUnsetEnvironmentMethod} 做引用比较，但两个 Method 分别来自
     * 两次 DexKit 查询，是不同实例，排除永远不生效（等于 unset 也被当成 set 调了一遍）。
     */
    private static boolean isSameMethod(Method a, Method b) {
        if (a == null || b == null) {
            return false;
        }
        return a.equals(b) || (a.getName().equals(b.getName())
            && Arrays.equals(a.getParameterTypes(), b.getParameterTypes()));
    }
}
