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
package com.sevtinge.hyperceiler.libhook.rules.securitycenter.other

import android.net.Uri
import android.os.Bundle
import com.sevtinge.hyperceiler.common.log.XposedLog
import com.sevtinge.hyperceiler.libhook.base.BaseHook
import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam
import io.github.lingqiqi5211.ezhooktool.xposed.dsl.createHooks
import io.github.lingqiqi5211.ezhooktool.xposed.java.IMethodHook
import java.lang.reflect.Method

object FuckRiskPkg : BaseHook() {

    private const val GUARD_AUTHORITY = "guard"
    private const val CALL_GET_RISK_APP_DATA = "getRiskAppData"

    private var legacyRiskPkgMethods: List<Method> = emptyList()

    override fun useDexKit(): Boolean = true

    override fun initDexKit(): Boolean {
        // 旧锚点：OS4 已删除 riskPkgList / key_virus_pkg_list / show_virus_notification 三个字符串，
        // 名单逻辑整体迁到 guardprovider，所以这里降级为 optionalMemberList —— 有就用它兜底，
        // 没有也不再让整条规则以 "required DexKit member list not found" 失败。
        legacyRiskPkgMethods = optionalMemberList("FuckRiskPkgLegacy") {
            it.findMethod {
                matcher {
                    usingEqStrings(
                        "riskPkgList", "key_virus_pkg_list", "show_virus_notification"
                    )
                }
            }
        }
        return true
    }

    override fun init() {
        // 新逻辑（OS4）：风险名单搬到 guardprovider 后，安全中心只剩一次跨进程查询 ——
        //   getContentResolver().call(Uri.parse("content://guard"), "getRiskAppData", "", null)
        // 拿到 Bundle 再读 riskData（见安全中心 eo/b 的 c(..)）。
        // 直接拦这个调用返回空 Bundle，名单恒为空；不依赖任何已被删除的混淆锚点，
        // 也不需要 guardprovider 进程活着。
        val resolverClass = findClassIfExists("android.content.ContentResolver")
        if (resolverClass == null) {
            XposedLog.e(
                TAG, getPackageName(),
                "FuckRiskPkg: android.content.ContentResolver 不存在，风险名单无法清空"
            )
        } else {
            val callMethod = findMethodExactIfExists(
                resolverClass,
                "call",
                Uri::class.java,
                String::class.java,
                String::class.java,
                Bundle::class.java
            )
            if (callMethod == null) {
                XposedLog.e(
                    TAG, getPackageName(),
                    "FuckRiskPkg: ContentResolver#call(Uri,String,String,Bundle) 不存在，风险名单无法清空"
                )
            } else {
                hookMethod(callMethod, object : IMethodHook {
                    override fun after(param: HookParam) {
                        val args = param.args
                        if (args.size < 2) return
                        val uri = args[0] as? Uri ?: return
                        if (uri.authority != GUARD_AUTHORITY) return
                        val called = args[1] as? String ?: return
                        if (called != CALL_GET_RISK_APP_DATA) return
                        param.result = Bundle.EMPTY
                        XposedLog.d(
                            TAG, getPackageName(),
                            "FuckRiskPkg: 拦截 $GUARD_AUTHORITY#$CALL_GET_RISK_APP_DATA，风险名单返回空"
                        )
                    }
                })
            }
        }

        // 旧锚点兜底：老系统（名单仍在安全中心本地）继续用原来的 returnConstant(null)
        if (legacyRiskPkgMethods.isNotEmpty()) {
            XposedLog.d(
                TAG, getPackageName(),
                "FuckRiskPkg: 旧锚点仍可用（${legacyRiskPkgMethods.size} 个方法），一并 hook 为空"
            )
            legacyRiskPkgMethods.createHooks {
                returnConstant(null)
            }
        }
    }
}
