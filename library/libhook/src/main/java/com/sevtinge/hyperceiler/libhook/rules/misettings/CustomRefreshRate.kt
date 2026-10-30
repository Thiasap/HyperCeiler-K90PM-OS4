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
package com.sevtinge.hyperceiler.libhook.rules.misettings

import com.sevtinge.hyperceiler.common.log.XposedLog
import com.sevtinge.hyperceiler.libhook.base.BaseHook
import com.sevtinge.hyperceiler.libhook.utils.hookapi.tool.StaticFieldCompat
import io.github.lingqiqi5211.ezhooktool.xposed.dsl.createHook
import java.lang.reflect.Method
import java.lang.reflect.Modifier

object CustomRefreshRate : BaseHook() {
    override fun useDexKit() = true

    override fun initDexKit(): Boolean {
        resultMethod
        return true
    }

    private val resultMethod by lazy<Method> {
        // HyperOS 4（MISettings）里 "btn_preferce_category" 被两个方法引用：
        //   NewRefreshRateFragment#C(Z)V                                ← 真正的开关
        //   NewRefreshRateFragment#onCreatePreferences(Bundle,String)V  ← 只是取 PreferenceCategory
        // 老代码用 .single()，两处命中会抛 NonUniqueResultException，整条规则在 initDexKit
        // 阶段就失败、一个 hook 都装不上。用 paramCount = 1 精确挑出 C(Z)（另一个是 2 参）。
        // C(true) 会把「自定义高刷新率」条目加进 btn_preferce_category 分类，C(false) 移除。
        requiredMember("CustomRefreshRate") {
            it.findMethod {
                matcher {
                    addEqString("btn_preferce_category")
                    paramCount = 1
                }
            }.single()
        }
    }

    override fun init() {
        resultMethod.createHook {
            before {
                it.args[0] = true
            }
        }
        // RefreshRateActivity 里的 static final Boolean = Boolean.valueOf(d7.a.F("support_smart_fps"))，
        // onCreate 据此决定挂 NewRefreshRateFragment 还是 OldRefreshRateFragment。
        // Android 14+ 直接 Field.set 写 static final 会被 ART 拒绝，改走 StaticFieldCompat（Unsafe），
        // 失败必须报 E，不允许静默。
        val resultClass = findClass("com.xiaomi.misettings.display.RefreshRate.RefreshRateActivity")
        val field = resultClass.declaredFields.firstOrNull {
            Modifier.isFinal(it.modifiers) && Modifier.isStatic(it.modifiers)
        }
        if (field == null) {
            XposedLog.e(TAG, getPackageName(),
                "CustomRefreshRate: RefreshRateActivity 里没有 static final 字段，新刷新率界面未能强制启用")
        } else if (!StaticFieldCompat.setStaticObject(resultClass, field.name, true)) {
            XposedLog.e(TAG, getPackageName(),
                "CustomRefreshRate: 写入 ${field.name} 失败（unsafeAvailable=${StaticFieldCompat.isAvailable()}），新刷新率界面未能强制启用")
        }
    }
}
