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
package com.sevtinge.hyperceiler.libhook.rules.voicetrigger

import android.annotation.SuppressLint
import com.sevtinge.hyperceiler.common.log.XposedLog
import com.sevtinge.hyperceiler.common.utils.PrefsBridge
import com.sevtinge.hyperceiler.libhook.base.BaseHook
import io.github.lingqiqi5211.ezhooktool.xposed.dsl.createHook
import java.lang.reflect.Method
import java.lang.reflect.Modifier

object BypassUDKWordLegalCheck : BaseHook() {
    override fun useDexKit() = true
    private var bypassPangaeaWordCheck: Method? = null
    private var bypassLegacyTrainingCheck: Method? = null
    private var bypassDefineWordCheck: Method? = null
    private var bypassOnlineAccuracyResult: Method? = null
    private var bypassNetworkStateCheckForUdkEnroll: Method? = null

    override fun initDexKit(): Boolean {
        bypassPangaeaWordCheck = optionalMember("BypassPangaeaWordCheck") {
            it.findMethod {
                matcher {
                    usingEqStrings("PangaeaTrainingSession", "onlineQuery=")
                    returnType = "java.lang.Boolean"
                }
            }.single()
        }
        bypassLegacyTrainingCheck = optionalMember("BypassLegacyTrainingCheck") {
            it.findMethod {
                matcher {
                    usingEqStrings("LegacyTrainingSession", "onlineQuery=")
                    returnType = "java.lang.Boolean"
                }
            }.single()
        }
        bypassDefineWordCheck = optionalMember("BypassDefineWordCheck") {
            it.findMethod {
                matcher {
                    usingEqStrings(
                        "https://i.ai.mi.com/api/skillstore/assistant/store/visitors/checkWakeUpWord",
                        "NetUtils",
                        "checkUDKWordLegal, callResult="
                    )
                    returnType = "boolean"
                }
            }.single()
        }
        // 新逻辑优先，且不依赖域名：合规检查的日志串 "getUDKWordLegal, result=" 在 OS4 的
        // VoiceTrigger.apk 里全 dex 唯一（v0.y#a(String, Context)String），域名反而换过一次
        // （i.ai.mi.com → i.xiaomixiaoai.com），所以先用无域名的串锚定。
        bypassOnlineAccuracyResult = optionalMember("BypassOnlineAccuracyResultOs4") {
            it.findMethod {
                matcher {
                    usingEqStrings("getUDKWordLegal, result=")
                    returnType = "java.lang.String"
                }
            }.single()
        } ?: optionalMember("BypassOnlineAccuracyResultOs4Domain") {
            // 兜底：万一上面那条日志串被删，再用「域名 + getUDKEnrollWordLegal can't get result」定位
            it.findMethod {
                matcher {
                    usingEqStrings(
                        "https://i.xiaomixiaoai.com/api/skillstore/assistant/store/visitors/checkWakeUpWord",
                        "getUDKEnrollWordLegal can't get result"
                    )
                    returnType = "java.lang.String"
                }
            }.single()
        } ?: optionalMember("BypassOnlineAccuracyResult") {
            it.findMethod {
                matcher {
                    usingEqStrings(
                        "https://i.ai.mi.com/api/skillstore/assistant/store/visitors/checkWakeUpWord",
                        "NetUtils",
                        "getUDKEnrollWordLegal can't get result"
                    )
                    returnType = "java.lang.String"
                }
            }.single()
        }
        bypassNetworkStateCheckForUdkEnroll = optionalMember("BypassNetworkStateCheckForUdkEnroll") {
            it.findMethod {
                matcher {
                    usingEqStrings("connectivity")
                    paramCount = 1
                    paramTypes("android.content.Context")
                    modifiers = Modifier.STATIC
                    returnType = "boolean"
                    opNames = listOf(
                        "const-string",
                        "invoke-virtual",
                        "move-result-object",
                        "check-cast",
                        "const/4",
                        "if-nez",
                        "return",
                        "invoke-virtual"
                    )

                }
            }.single()
        }
        return true
    }

    @SuppressLint("DefaultLocale")
    override fun init() {
        // 根据对应的唤醒词得到其精度，并返回其是否可用
        val accUser = PrefsBridge.getInt("voicetrigger_accuracy_percent", 70).toFloat() / 100
        val accuracyJson = "{\"data\":{\"status\":0,\"msg\":\"\",\"accuracy\":\"" + String.format(
            "%.1f",
            accUser
        ) + "\"}}"

        // Pangaea / Legacy 两个引擎的「联网检查」在 OS4 上已经不存在：全 dex 里没有任何返回
        // java.lang.Boolean 的方法，锚点 onlineQuery= / LegacyTrainingSession 也已删除，
        // 这部分职责由下面的「联网状态检查」接手，所以只报 W。
        hookReturn(bypassPangaeaWordCheck, "BypassPangaeaWordCheck", true, obsolete = true)
        hookReturn(bypassLegacyTrainingCheck, "BypassLegacyTrainingCheck", true, obsolete = true)
        // 「判断唤醒词是否合规」：OS4 的旧锚点 checkUDKWordLegal, callResult= 已删，
        // 合规判断并入下面的联网合规检查（返回值 JSON 里 status=0 即合规），同样只报 W。
        hookReturn(bypassDefineWordCheck, "BypassDefineWordCheck", true, obsolete = true)
        // 核心：把联网合规检查的返回 JSON 换成「status=0 + 用户设定的精度」，
        // 自定义唤醒词才能既过合规检查又过精度门槛。
        hookReturn(bypassOnlineAccuracyResult, "BypassOnlineAccuracyResult", accuracyJson)
        // 禁止判断当前系统网络状态
        hookReturn(bypassNetworkStateCheckForUdkEnroll, "BypassNetworkStateCheckForUdkEnroll", true)
    }

    /**
     * 逐个 hook 并如实记录结果。
     * <p>
     * 旧实现每个子项都套了一层 runCatching 且没有任何日志，hook 失败或锚点失配时完全静默——
     * 功能没生效却一条日志都没有。这里改为：锚点缺失必报（核心子项 E、已被系统新实现取代的 W），
     * hook 抛异常也报 E。
     */
    private fun hookReturn(method: Method?, name: String, value: Any?, obsolete: Boolean = false) {
        if (method == null) {
            if (obsolete) {
                XposedLog.w(TAG, packageName, "$name: 该系统版本已无此检查方法（由新实现取代），子项跳过")
            } else {
                XposedLog.e(TAG, packageName, "$name: 未匹配到目标方法，该子项未生效")
            }
            return
        }
        runCatching { method.createHook { returnConstant(value) } }
            .onSuccess { XposedLog.d(TAG, packageName, "$name: hooked $method") }
            .onFailure { XposedLog.e(TAG, packageName, "$name: hook 失败", it) }
    }
}
