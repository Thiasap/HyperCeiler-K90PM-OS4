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
        // OS4 里 riskPkgList / key_virus_pkg_list / show_virus_notification 三个字符串已全部消失
        // （安全中心的风险应用逻辑被重写进 com.miui.antivirus），这里改成可选匹配：
        // OS3 及更早版本照旧命中并 hook，OS4 上空列表直接跳过，不再让规则以 initDexKit failed 报错。
        optionalMemberList("FuckRiskPkg") {
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
        if (pkg.isEmpty()) return
        pkg.createHooks {
            returnConstant(null)
        }
    }
}
