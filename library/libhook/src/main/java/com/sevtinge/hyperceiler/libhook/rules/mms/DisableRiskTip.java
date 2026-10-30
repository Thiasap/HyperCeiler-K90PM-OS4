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

package com.sevtinge.hyperceiler.libhook.rules.mms;

import static com.sevtinge.hyperceiler.libhook.utils.hookapi.tool.AppsTool.getPackageVersionCode;

import android.text.TextUtils;

import com.sevtinge.hyperceiler.common.log.XposedLog;
import com.sevtinge.hyperceiler.common.utils.PrefsBridge;
import com.sevtinge.hyperceiler.libhook.base.BaseHook;
import io.github.lingqiqi5211.ezhooktool.xposed.java.IMethodHook;
import com.sevtinge.hyperceiler.libhook.utils.hookapi.dexkit.IDexKit;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.result.MethodData;
import org.luckypray.dexkit.result.base.BaseData;

import java.lang.reflect.Method;

import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam;


public class DisableRiskTip extends BaseHook {
    /** SmartContact / MessageItemExtra 里风险类型的取值，见 Constants.RiskyPhoneType */
    private static final String RISK_TYPE_OVERSEAS = "11";  // ABROAD_TYPE_PHONE：境外来电/境外短信风险
    private static final String RISK_TYPE_DEFRAUD = "12";   // RISK_TYPE_DEFRAUD：诈骗号码
    private static final String FIELD_RISK_TYPE = "mRiskType";

    private static final String CLASS_YELLOW_PAGE_CONTACT_FETCHER =
        "com.miui.smsextra.internal.sdk.xiaomi.YellowpageContactFetcher";
    private static final String METHOD_FILL_YELLOW_PAGE_CONTACT = "fillYellowPageContact";

    private Method mFillSmartContactByB2cMethod;
    private Method mFillYellowPageContactMethod;
    private Method mFillYellowPageContactOs4Method;

    @Override
    protected boolean useDexKit() {
        return true;
    }

    /**
     * HyperOS 4（短信 18.0.0.42）里旧查询的第二条已经 0 命中，导致整条规则在 initDexKit 阶段
     * 直接抛错、两条 fill hook 全部装不上，两个开关等于完全没接线。原因：
     * - "fillYellowPageContact: " 这个带冒号的日志串已经删掉，dex 里只剩不带冒号的
     * "fillYellowPageContact"，所以 usingStrings("fillYellowPageContact: ", "ContactFetcher") 查空；
     * - 目标方法本身没变，就是 YellowpageContactFetcher#fillYellowPageContact(SmartContact,
     * YellowPagePhone)V（private static，2 参 void），而类名和协议类的类名都没有混淆，
     * 可以直接按「类名 + 方法名」定位，比字符串锚点稳。
     * <p>
     * 这里两条旧查询原样保留（老系统仍按字符串命中），只是降为 optional；
     * OS4 再按类名反射兜底，全部失配时在 init() 里打 E 级日志，不再让整条规则连坐失效。
     */
    @Override
    protected boolean initDexKit() {
        mFillSmartContactByB2cMethod = optionalMember("Method1", new IDexKit() {
            @Override
            public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                MethodData methodData = bridge.findMethod(FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .usingStrings("fillSmartContactByB2c: old smart contact is not null")
                    )).singleOrNull();
                return methodData;
            }
        });
        mFillYellowPageContactMethod = optionalMember("Method2", new IDexKit() {
            @Override
            public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                MethodData methodData = bridge.findMethod(FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .usingStrings("fillYellowPageContact: ", "ContactFetcher")
                        .returnType(void.class)
                        .paramCount(2)
                    )).singleOrNull();
                return methodData;
            }
        });
        return true;
    }

    @Override
    public void init() {
        // ① 号码风险谓词：把「境外」与「诈骗」分别交给自己的开关
        //   SmartContact#isRiskyNumber  : mRiskType == "11" 且当前运营商是 460 网
        //   SmartContact#isDefraudNumber: mRiskType == "12"
        findAndHookMethod("com.miui.smsextra.sdk.SmartContact", "isRiskyNumber", new IMethodHook() {
            @Override
            public void before(HookParam param) {
                if (PrefsBridge.getBoolean("mms_disable_overseas_risk_tip")) {
                    param.setResult(false);
                }
            }
        });
        findAndHookMethod("com.miui.smsextra.sdk.SmartContact", "isDefraudNumber", new IMethodHook() {
            @Override
            public void before(HookParam param) {
                if (PrefsBridge.getBoolean("mms_disable_fraud_risk_tip")) {
                    param.setResult(false);
                }
            }
        });
        // ② 黄页侧的同一组谓词（HyperOS 2 起才拆出 internal.sdk.xiaomi.YellowPagePhone）
        if (getPackageVersionCode(getLpparam()) >= 170000000) {
            findAndHookMethod("com.miui.smsextra.internal.sdk.xiaomi.YellowPagePhone", "isRiskyNumber", new IMethodHook() {
                @Override
                public void before(HookParam param) {
                    if (PrefsBridge.getBoolean("mms_disable_overseas_risk_tip")) {
                        param.setResult(false);
                    }
                }
            });
            findAndHookMethod("com.miui.smsextra.internal.sdk.xiaomi.YellowPagePhone", "isDefraudNumber", new IMethodHook() {
                @Override
                public void before(HookParam param) {
                    if (PrefsBridge.getBoolean("mms_disable_fraud_risk_tip")) {
                        param.setResult(false);
                    }
                }
            });
        }
        // ③ 联系人信息填充完成后清掉风险类型：这是真正决定消息列表/会话头像要不要显示
        //   「境外短信」「诈骗短信」提示的字段（SmartContact#mRiskType）
        if (mFillSmartContactByB2cMethod != null) {
            XposedLog.d(TAG, getPackageName(), "Current hooking method is " + mFillSmartContactByB2cMethod);
            hookMethod(mFillSmartContactByB2cMethod, new IMethodHook() {
                @Override
                public void after(HookParam param) {
                    clearRiskType(param);
                }
            });
        }
        if (mFillYellowPageContactMethod == null) {
            mFillYellowPageContactOs4Method = findFillYellowPageContactMethod();
        }
        Method fillYellowPageContact = mFillYellowPageContactMethod != null
            ? mFillYellowPageContactMethod : mFillYellowPageContactOs4Method;
        if (fillYellowPageContact != null) {
            XposedLog.d(TAG, getPackageName(), "Current hooking method is " + fillYellowPageContact);
            hookMethod(fillYellowPageContact, new IMethodHook() {
                @Override
                public void after(HookParam param) {
                    clearRiskType(param);
                }
            });
        }
        // ④ 两个 fill 点一个都没拿到必须报 E：说明风险提示字段无从下手，规则实际未生效
        if (mFillSmartContactByB2cMethod == null && fillYellowPageContact == null) {
            XposedLog.e(TAG, getPackageName(),
                "DisableRiskTip: 两个联系人填充点均未匹配（x3.a#b / YellowpageContactFetcher#fillYellowPageContact），短信风险提示无法清除");
        }
    }

    /**
     * OS4 按「类名 + 方法名」直接定位 private static void fillYellowPageContact(SmartContact, YellowPagePhone)。
     * 类名与两个参数类名都没有混淆，比字符串锚点稳定。
     */
    private Method findFillYellowPageContactMethod() {
        Class<?> clazz = findClassIfExists(CLASS_YELLOW_PAGE_CONTACT_FETCHER);
        if (clazz == null) {
            return null;
        }
        for (Method method : clazz.getDeclaredMethods()) {
            if (METHOD_FILL_YELLOW_PAGE_CONTACT.equals(method.getName())
                && method.getReturnType() == void.class
                && method.getParameterCount() == 2) {
                return method;
            }
        }
        return null;
    }

    /**
     * 把 SmartContact#mRiskType 里的 11（境外）/ 12（诈骗）按对应开关清掉，
     * 其他取值（例如 "2" 官方号码）不动。
     * <p>
     * 旧实现是 {@code getObjectField(...) == "11"} 的引用比较 + 一条在 if 外面的无条件
     * setObjectField，等于开关从来没生效过（mRiskType 永远被清空）。这里改成按值比较、
     * 按开关放行，两个开关才真正起作用。
     */
    private void clearRiskType(HookParam param) {
        Object[] args = param.getArgs();
        if (args == null || args.length == 0 || args[0] == null) {
            return;
        }
        Object smartContact = args[0];
        Object riskType = getObjectField(smartContact, FIELD_RISK_TYPE);
        if (!(riskType instanceof String)) {
            return;
        }
        String value = (String) riskType;
        boolean overseas = RISK_TYPE_OVERSEAS.equals(value)
            && PrefsBridge.getBoolean("mms_disable_overseas_risk_tip");
        boolean defraud = RISK_TYPE_DEFRAUD.equals(value)
            && PrefsBridge.getBoolean("mms_disable_fraud_risk_tip");
        if (overseas || defraud) {
            setObjectField(smartContact, FIELD_RISK_TYPE, "");
            XposedLog.d(TAG, getPackageName(), "clear mRiskType(" + value + ") on " + smartContact.getClass().getName());
        }
    }
}
