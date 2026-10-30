/*
 * This file is part of HyperCeiler.

 * HyperCeiler is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.

 * Copyright (C) 2023-2026 HyperCeiler Contributions
 */
package com.sevtinge.hyperceiler.libhook.rules.guardprovider;

import android.os.Bundle;

import com.sevtinge.hyperceiler.common.log.XposedLog;
import com.sevtinge.hyperceiler.libhook.base.BaseHook;
import io.github.lingqiqi5211.ezhooktool.xposed.java.IMethodHook;

import java.lang.reflect.Method;

import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam;

/**
 * 风险应用名单（guardprovider 侧）。
 * <p>
 * HyperOS 4 把「风险/病毒应用名单」从安全中心搬进了 guardprovider：
 * 安全中心（eo.b）、安装器（c5.n）等通过
 * {@code ContentResolver.call(uri, "getRiskAppData", ...)} 拿名单，名单本身是
 * 云端扫描结果落在 guardprovider 的 risk_gray_result_db 里，由 GuardProvider#call 读出来
 * 拼成 {@code Bundle{riskData: JSONArray 字符串}} 返回。
 * <p>
 * 所以安全中心侧的 FuckRiskPkg 规则（riskPkgList / key_virus_pkg_list /
 * show_virus_notification 三个锚点）在 OS4 上必然 0 命中——它 hook 的静态名单已经不存在了。
 * 真正等价的拦截点在这里：把 getRiskAppData 的返回值换成空数组，
 * 语义与「云端扫描没发现任何风险应用」完全一致，调用方拿到的 Bundle 结构和真实空列表一致
 * （已用 {@code content call --uri content://guard --method getRiskAppData} 验证过空结果的形状
 * 就是 {@code Bundle[{riskData=[]}]}），不会让调用方以为接口坏了。
 * <p>
 * GuardProvider 是稳定类名（未混淆），无需 DexKit；类/方法缺失由框架打 E 级 Hook Failed。
 */
public class DisableRiskAppData extends BaseHook {
    private static final String GUARD_PROVIDER_CLASS = "com.miui.guardprovider.GuardProvider";
    private static final String METHOD_GET_RISK_APP_DATA = "getRiskAppData";
    private static final String KEY_RISK_DATA = "riskData";
    private static final String EMPTY_RISK_DATA = "[]";

    @Override
    public void init() {
        Class<?> guardProvider = findClassIfExists(GUARD_PROVIDER_CLASS);
        if (guardProvider == null) {
            XposedLog.e(TAG, getPackageName(),
                "DisableRiskAppData: " + GUARD_PROVIDER_CLASS + " 不存在，风险应用名单未拦截");
            return;
        }
        Method call = findMethodExactIfExists(guardProvider, "call", String.class, String.class, Bundle.class);
        if (call == null) {
            XposedLog.e(TAG, getPackageName(),
                "DisableRiskAppData: GuardProvider#call(String, String, Bundle) 不存在，风险应用名单未拦截");
            return;
        }
        XposedLog.d(TAG, getPackageName(), "Current hooking method is " + call);
        hookMethod(call, new IMethodHook() {
            @Override
            public void before(HookParam param) {
                Object[] args = param.getArgs();
                if (args == null || args.length == 0 || !METHOD_GET_RISK_APP_DATA.equals(args[0])) {
                    return;
                }
                Bundle result = new Bundle();
                result.putString(KEY_RISK_DATA, EMPTY_RISK_DATA);
                param.setResult(result);
                XposedLog.d(TAG, getPackageName(), "getRiskAppData 已置空");
            }
        });
    }
}
