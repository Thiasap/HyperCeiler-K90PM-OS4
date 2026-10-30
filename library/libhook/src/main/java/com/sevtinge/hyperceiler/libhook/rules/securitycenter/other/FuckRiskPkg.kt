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

import com.sevtinge.hyperceiler.libhook.base.BaseHook
import io.github.lingqiqi5211.ezhooktool.xposed.dsl.createHooks
import java.lang.reflect.Method

object FuckRiskPkg : BaseHook() {

    override fun useDexKit(): Boolean = true

    override fun initDexKit(): Boolean {
        pkg
        return true
    }

    private val pkg by lazy<List<Method>> {
        // 反编译 OS4 安全中心（8.x）确认：riskPkgList / key_virus_pkg_list / show_virus_notification
        // 三个字符串已全部删除，风险应用名单逻辑整体迁出了本模块 scope ——
        // 安全中心现在通过 eo.b 经 content://guard 调 com.miui.guardprovider 的
        // "getRiskAppData" 拿名单，名单真正住在 guardprovider 进程里。
        // 因此本规则在 OS4 上必然 0 命中：保持 requiredMemberList，让框架打 E 级
        // 「required DexKit member list not found」如实暴露失配；
        // （44b090c76 曾把它降级为 optionalMemberList + 空列表静默 return，
        //  属于「掩耳盗铃」——功能失效却一条日志都没有，已回退。）
        // TODO(OS4 后续): 在 com.miui.guardprovider scope 新增规则 hook guardprovider
        //  侧的名单查询（见 handover/os4-hook-review-2026-10-31.md）。
        requiredMemberList("FuckRiskPkg") {
            it.findMethod {
                matcher {
                    usingEqStrings(
                        "riskPkgList", "key_virus_pkg_list", "show_virus_notification"
                    )
                }
            }
        }
    }

    override fun init() {
        pkg.createHooks {
            returnConstant(null)
        }
    }
}
