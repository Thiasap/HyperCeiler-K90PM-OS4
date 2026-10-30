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
package com.sevtinge.hyperceiler.libhook.rules.packageinstaller

import android.content.Context
import com.sevtinge.hyperceiler.common.log.XposedLog
import com.sevtinge.hyperceiler.libhook.base.BaseHook
import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam
import io.github.lingqiqi5211.ezhooktool.xposed.dsl.createHook
import io.github.lingqiqi5211.ezhooktool.xposed.java.IMethodHook
import java.lang.reflect.Method

object DisableCloudCheck : BaseHook() {

    override fun useDexKit() = true

    private lateinit var fetchMethods: List<Method>
    private lateinit var cloudParamsClass: Class<*>
    private lateinit var cloudSuccessClass: Class<*>

    override fun initDexKit(): Boolean {
        method1
        method2
        cloudParamsClass = findClass("com.miui.packageInstaller.model.CloudParams")
        cloudSuccessClass = findClass("com.miui.packageInstaller.model.CloudResult\$Success")
        // 云校验请求，签名对应：
        // public final java.lang.Object c(Context, CallingPackage, int, ApkInfo, HashMap, Continuation)
        // OS4 把这个 Continuation 一起混淆成了 x3.d，老版本写死 "kotlin.coroutines.Continuation" 的
        // 精确查询会返回空并让整条规则失效，所以这里把两个易变位置（CallingPackage、Continuation）
        // 用 null 通配，只锁定 Context / int / ApkInfo / HashMap 四个稳定位置；再用请求参数里的
        // 三个字面量做锚（与 DisableAppInfoUpload 里同一条 API 的写法一致）避免误命中。
        // 找不到就让 initDexKit 抛错，由框架打 E 级日志（"Skip hook because initDexKit failed"），不静默跳过。
        fetchMethods = requiredMemberList("Fetch") { bridge ->
            bridge.findMethod {
                matcher {
                    paramCount = 6
                    paramTypes(
                        Context::class.java,
                        null,
                        Int::class.javaPrimitiveType,
                        findClass("com.miui.packageInstaller.model.ApkInfo"),
                        HashMap::class.java,
                        null
                    )
                    usingStrings("device_type", "installationMode", "apk_bit")
                    returnType = Any::class.java.name
                }
            }
        }
        return true
    }

    // OS4 安装器的底部按钮换了实现（install_btn + 16 已经匹配不到，method2 的匹配串本身也是
    // 被截断过的字面量），这两条只能做成可选：匹配不到时在 init() 里打 E 日志说明，
    // 不影响下面真正的云校验 hook。
    private val method1 by lazy<Method?> {
        optionalMember("NoNetworkInstallBtn") {
            it.findMethod {
                matcher {
                    usingStrings("install_btn")
                    usingNumbers(16)
                }
            }.singleOrNull()
        }
    }

    private val method2 by lazy<Method?> {
        optionalMember("NormalInstallBtn") {
            it.findMethod {
                matcher {
                    usingStrings("getString(if (shouldUseU…e R.string.start_install)")
                }
            }.singleOrNull()
        }
    }

    override fun init() {
        hookInstallButtons()
        hookCloudCheck()
        hookNetworkErrorRiskTip()
    }

    /**
     * 老逻辑：网络异常页的「安装」按钮直接改调普通安装按钮。
     */
    private fun hookInstallButtons() {
        val m1 = method1
        val m2 = method2
        if (m1 == null || m2 == null) {
            XposedLog.e(
                TAG, packageName,
                "NoNetworkInstallBtn/NormalInstallBtn 未匹配，跳过按钮联动（不影响云校验）"
            )
            return
        }
        hookMethod(m1, object : IMethodHook {
            override fun before(param: HookParam) {
                callMethod(param.thisObject, m2.name, param.args[0])
                param.result = null
            }
        })
    }

    /**
     * 云校验（interceptcheck）请求直接返回 `CloudResult.Success(CloudParams())`，等价于「联网检测通过」。
     *
     * 云校验结果为空时，安装页 FullSafeHelper 会落到「网络异常」策略，用户看到的就是
     * 「风险提示 —— 当前网络环境不佳，无法进行联网检测…」，且该页两个分支都装不上：
     * 增强安全模式/禁止安装名单 -> 只剩取消；否则 -> 二次确认，点「继续」也只露出
     * 右上角「⋮ > 单次安装授权」菜单项，不会开始安装。
     */
    private fun hookCloudCheck() {
        fetchMethods.forEach { method ->
            try {
                method.createHook {
                    replace { param ->
                        try {
                            val cloudParams = cloudParamsClass.getDeclaredConstructor()
                                .apply { isAccessible = true }
                                .newInstance()
                            cloudSuccessClass.getDeclaredConstructor(cloudParamsClass)
                                .apply { isAccessible = true }
                                .newInstance(cloudParams)
                        } catch (e: Exception) {
                            XposedLog.e(TAG, packageName, "构造 CloudResult.Success 失败，回退原方法", e)
                            BaseHook.invokeOriginalMethod(
                                param.executable as Method,
                                param.thisObject,
                                param.args
                            )
                        }
                    }
                }
            } catch (e: Exception) {
                XposedLog.e(TAG, packageName, "hook 云校验请求 $method 失败", e)
            }
        }
    }

    /**
     * 兜底：万一云校验 hook 在新版本上又失配，安装页仍会走 `t2.r#a2(q2.l)`，两条分支都装不上
     * （见上）。这里把 `a2` 换成 `e2`：只显示一个安装按钮，点击直接安装
     * （setupInstallButton(..., needDoubleCheck = false)），不再弹「网络环境不佳」。
     *
     * 类名/方法名是 R8 混淆产物，找不到就打 E 日志，说明兜底失效。
     * 注意 dex 里真实类名是小写 `Lt2/r;`：jadx 在 Windows 上把 t2/ 与 T2/ 输出进同一目录，
     * 照目录名写成 "T2.r" 会找不到类。
     */
    private fun hookNetworkErrorRiskTip() {
        val page = findClassIfExists("t2.r") ?: findClassIfExists("T2.r")
        if (page == null) {
            XposedLog.e(TAG, packageName, "未找到安装页类 t2.r，网络风险弹窗兜底失效")
            return
        }
        val declared = page.declaredMethods
        val networkTip = declared.firstOrNull { it.name == "a2" && it.parameterCount == 1 }
        val plainInstall = networkTip?.let { tip ->
            declared.firstOrNull {
                it.name == "e2" && it.parameterTypes.contentEquals(tip.parameterTypes)
            }
        }
        if (networkTip == null || plainInstall == null) {
            XposedLog.e(TAG, packageName, "${page.name} 的 a2/e2 未找到，网络风险弹窗兜底失效")
            return
        }
        try {
            networkTip.createHook {
                replace { param -> plainInstall.invoke(param.thisObject, *param.args) }
            }
        } catch (e: Exception) {
            XposedLog.e(TAG, packageName, "hook ${page.name}#a2 失败", e)
        }
    }
}
