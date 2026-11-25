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
package com.sevtinge.hyperceiler.libhook.rules.securitycenter

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.util.ArrayMap
import com.sevtinge.hyperceiler.common.log.XposedLog
import com.sevtinge.hyperceiler.libhook.base.BaseHook
import io.github.lingqiqi5211.ezhooktool.core.findMethod
import io.github.lingqiqi5211.ezhooktool.xposed.dsl.getObjectField
import io.github.lingqiqi5211.ezhooktool.core.loadClass
import io.github.lingqiqi5211.ezhooktool.xposed.dsl.createHook
import org.lsposed.hiddenapibypass.HiddenApiBypass

class RemoveConversationBubbleSettingsRestriction : BaseHook() {
    @SuppressLint("PrivateApi")
    override fun init() {
        loadClass("com.miui.bubbles.settings.BubblesSettings").findMethod { name("getDefaultBubbles") }.createHook {
                before { param ->
                    // OS4 上 getFreeformSuggestionList / BubbleApp 的构造与 setChecked 签名都可能变，
                    // 任一步失败都不能让 before 抛出去（会打断系统原本的气泡列表构建），
                    // 也不能静默：统一在这里如实上报，让系统走默认逻辑。
                    try {
                        val classBubbleApp = loadClass("com.miui.bubbles.settings.BubbleApp")
                        val arrayMap = ArrayMap<String, Any>()
                        val mContext =
                            param.thisObject.getObjectField("mContext") as Context
                        val mCurrentUserId =
                            param.thisObject.getObjectField("mCurrentUserId") as Int
                        val freeformSuggestionList = suggestBubblePackages(mContext)
                        if (freeformSuggestionList.isNotEmpty()) {
                            for (str in freeformSuggestionList) {
                                val bubbleApp = classBubbleApp.getConstructor(
                                    String::class.java, Int::class.java
                                ).newInstance(str, mCurrentUserId)
                                classBubbleApp.getMethod("setChecked", Boolean::class.java)
                                    .invoke(bubbleApp, true)
                                arrayMap[str] = bubbleApp
                            }
                        }
                        param.result = arrayMap
                    } catch (t: Throwable) {
                        XposedLog.e(
                            TAG, getPackageName(),
                            "RemoveConversationBubbleSettingsRestriction: 构造气泡白名单失败，保持系统默认行为",
                            t
                        )
                    }
                }
            }
    }

    /**
     * 算出「气泡白名单」要列出的包名。
     *
     * 首选 MIUI 自己的 `MiuiMultiWindowUtils.getFreeformSuggestionList(Context)`；但它内部会走
     * `MiuiMultiWindowAdapter.calFreeformSuggestionList`，里面要
     *   ① `SecurityManager.getAllPrivacyApps(userId)`（MIUI 系统服务，普通进程多半没有权限）
     *   ② `MiuiMultiWindowUtils.queryUsageStats()`（要 PACKAGE_USAGE_STATS）
     *   ③ 若干 Settings.System/Secure 的读写
     * 4.0.8.0 上在安全中心进程里必然会在这条链里抛（设备日志：`getFreeformSuggestionList start` 打出来了，
     * 但 `end result` 永远没有），于是整段白名单构建被 catch 掉、功能等于没生效。
     *
     * 所以这里降级：MIUI 的算法不可用时，直接枚举「有桌面入口的应用」当作候选。
     * 本规则的目的只是**去掉白名单限制**，候选来源换成 PackageManager 并不改变语义，
     * 而且只依赖公开 API，不会再抛。两条路都空时才打 E。
     */
    @SuppressLint("PrivateApi")
    private fun suggestBubblePackages(context: Context): List<String> {
        try {
            val list = HiddenApiBypass.invoke(
                Class.forName("android.util.MiuiMultiWindowUtils"),
                null,
                "getFreeformSuggestionList",
                context
            ) as? List<*>
            val packages = list?.mapNotNull { it as? String }?.filter { it.isNotEmpty() }.orEmpty()
            if (packages.isNotEmpty()) return packages
            XposedLog.w(TAG, getPackageName(),
                "getFreeformSuggestionList 返回空，回退到枚举可启动应用")
        } catch (t: Throwable) {
            XposedLog.w(TAG, getPackageName(),
                "getFreeformSuggestionList 不可用（${t.javaClass.simpleName}: ${t.message}），回退到枚举可启动应用")
        }

        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val packages = LinkedHashSet<String>()
        try {
            context.packageManager.queryIntentActivities(intent, 0).forEach { info ->
                info.activityInfo?.packageName?.takeIf { it.isNotEmpty() }?.let { packages.add(it) }
            }
        } catch (t: Throwable) {
            XposedLog.e(TAG, getPackageName(), "枚举可启动应用失败", t)
        }
        packages.remove(context.packageName)
        if (packages.isEmpty()) {
            XposedLog.e(TAG, getPackageName(), "气泡候选列表为空，系统白名单保持默认")
        } else {
            XposedLog.d(TAG, getPackageName(), "气泡候选（枚举）：${packages.size} 个")
        }
        return packages.toList()
    }
}
