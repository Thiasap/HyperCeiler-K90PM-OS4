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

import android.app.Activity
import android.view.View
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.sevtinge.hyperceiler.common.log.XposedLog
import com.sevtinge.hyperceiler.libhook.base.BaseHook
import io.github.lingqiqi5211.ezhooktool.core.findMethod
import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam
import io.github.lingqiqi5211.ezhooktool.xposed.dsl.createAfterHook
import io.github.lingqiqi5211.ezhooktool.xposed.dsl.createHook
import io.github.lingqiqi5211.ezhooktool.xposed.dsl.setBooleanField
import io.github.lingqiqi5211.ezhooktool.xposed.java.IMethodHook
import java.lang.reflect.Field
import java.lang.reflect.Method

object DisableSafeModelTip : BaseHook() {

    private const val HINT_VIEW_OBJECT =
        "com.miui.packageInstaller.ui.listcomponets.FullSafeInstallHintViewObject"

    // 安装器 5.5.5.0.0 的资源 id：
    //   0x7f120229 -> string/install_safety_hint            「安全提醒」
    //   0x7f12021c -> string/install_hint_not_checked_hint  「该应用未经小米安全审核，建议优先使用应用商店下载。」
    // 只在标题/正文与这两条文案完全一致时才隐藏卡片，避免误伤「增强防护 / 企业管控」等同款卡片。
    private const val STR_SAFETY_HINT_TITLE = 0x7f120229
    private const val STR_SAFETY_HINT_CONTENT = 0x7f12021c

    // PackageInstallerActivity 的「未知来源」判定会读这个 intent extra
    private const val EXTRA_TRUSTED_SOURCE = "EXTRA_IS_TRUSTED_SOURCE"

    // 新安装页弹窗分发方法 t(int) 的类型码，10 = 「未知来源」确认
    private const val DIALOG_UNKNOWN_SOURCE = 10

    // 该分发方法方法体里唯一的日志串（OS4 实测全 dex 唯一命中），用来代替写死的混淆类名 l2.J
    private const val ANCHOR_UNKNOWN_SOURCE_DISPATCH = "Did not find app info for DLG_UNKNOWN_SOURCES: "

    override fun useDexKit() = true

    private var disableSafeModelTipMethod: Method? = null
    private var recyclerViewField: Field? = null
    private var unknownSourceCheckMethod: Method? = null
    private var unknownSourceDispatchMethod: Method? = null

    override fun initDexKit(): Boolean {
        disableSafeModelTipMethod = optionalMember("DisableSafeModelTip") {
            it.findMethod {
                matcher {
                    usingEqStrings($$"android.provider.MiuiSettings$Ad")
                }
            }.singleOrNull()
        }
        // OS4 的 SafeModeTipViewObject 父类里有 3 个 boolean 字段，原来 .single() 会抛
        // NonUniqueResultException: 3 并让整条规则失败。这里改成「取第一个，取不到就算了」，
        // 主开关（上面的方法 hook）仍然生效。
        recyclerViewField = optionalMember("RecyclerView") {
            it.findClass {
                matcher {
                    className = "com.miui.packageInstaller.ui.listcomponets.SafeModeTipViewObject"
                }
            }.findField {
                matcher {
                    type = "boolean"
                }
            }.firstOrNull()
        }
        // 「未知来源」确认的判定方法：方法体里读 intent 的 EXTRA_IS_TRUSTED_SOURCE，
        // 命中就把来源按「已信任」处理，不走弹窗分支。
        unknownSourceCheckMethod = optionalMember("UnknownSourceCheck") {
            it.findMethod {
                matcher {
                    usingStrings(EXTRA_TRUSTED_SOURCE)
                    paramCount = 0
                    returnType = "void"
                }
            }.singleOrNull()
        }
        // 新安装页的弹窗分发方法（原写法是写死 R8 混淆类名 l2.J + 方法名 t）。
        // 混淆名跨版本会漂移，改用方法体里唯一的日志串 + (int)V 签名定位，实测 1 命中。
        unknownSourceDispatchMethod = optionalMember("UnknownSourceDispatch") {
            it.findMethod {
                matcher {
                    usingEqStrings(ANCHOR_UNKNOWN_SOURCE_DISPATCH)
                    paramTypes("int")
                    returnType = "void"
                }
            }.single()
        }
        return true
    }

    override fun init() {
        disableSafeModelTipMethod?.createHook {
            replace { false }
        }

        recyclerViewField?.let { field ->
            runCatching {
                field.declaringClass.findMethod { name("a") }.createAfterHook {
                    it.thisObject.setBooleanField(field.name, false)
                }
            }
        }

        skipUnknownSourceConfirm()
        hideNotCheckedSafetyHint()
    }

    /**
     * 去掉「未知来源」确认弹窗（「来历不明的应用很可能会损害您的手机和个人数据…」继续 / 取消）。
     *
     * 安装页 `PackageInstallerActivity#l()` 的判断是
     * `f12503v || getIntent().getBooleanExtra("EXTRA_IS_TRUSTED_SOURCE", false)`
     * 为真就直接调 `t()` 开始安装，否则 `s()` 弹确认框。这里在判定前把 extra 置 true，
     * 让原方法自己走「已信任来源」分支——不绕过任何安全校验，只是把这一层确认去掉。
     */
    private fun skipUnknownSourceConfirm() {
        hookLegacyUnknownSourceCheck()
        hookNewUnknownSourceDialog()
    }

    /**
     * 老安装页 `PackageInstallerActivity#l()`：`f12503v || intent.getBooleanExtra("EXTRA_IS_TRUSTED_SOURCE")`
     * 为真就直接 `t()` 开始安装，否则 `s()` 弹确认框。
     */
    private fun hookLegacyUnknownSourceCheck() {
        val method = unknownSourceCheckMethod
        if (method == null) {
            XposedLog.e(TAG, packageName, "未找到「未知来源」判定方法，跳过该确认弹窗的适配")
            return
        }
        hookMethod(method, object : IMethodHook {
            override fun before(param: HookParam) {
                runCatching {
                    (param.thisObject as? Activity)?.intent?.putExtra(EXTRA_TRUSTED_SOURCE, true)
                }.onFailure {
                    XposedLog.e(TAG, packageName, "写入 $EXTRA_TRUSTED_SOURCE 失败", it)
                }
            }
        })
    }

    /**
     * OS4 默认走的新安装页 `NewInstallerPrepareActivity`：确认框不在 PackageInstallerActivity 里，
     * 而是由弹窗分发方法 `t(int)` 按类型码分发，10 = 「未知来源」（正文 resource `anonymous_source_warning`）。
     * 它的「继续」按钮只调 `p()`（= 继续安装），所以这里遇到 10 直接调 p()、不再弹窗。
     *
     * 类名/方法名都是 R8 混淆名（历史上是 `l2.J#t`），跨版本会漂移，所以不再写死：
     * 由 [ANCHOR_UNKNOWN_SOURCE_DISPATCH] 在 DexKit 里定位分发方法，`p()` 再从实例上按名字反射调用。
     * 定位失败时打 E 日志，不静默跳过。
     */
    private fun hookNewUnknownSourceDialog() {
        val dispatch = unknownSourceDispatchMethod
        if (dispatch == null) {
            XposedLog.e(
                TAG, packageName,
                "未找到新安装页的未知来源弹窗分发方法（锚点 $ANCHOR_UNKNOWN_SOURCE_DISPATCH），跳过该确认框"
            )
            return
        }
        hookMethod(dispatch, object : IMethodHook {
            override fun before(param: HookParam) {
                if ((param.args.getOrNull(0) as? Int) != DIALOG_UNKNOWN_SOURCE) return
                runCatching { callMethod(param.thisObject, "p") }
                    .onSuccess { param.result = null }
                    .onFailure {
                        XposedLog.e(TAG, packageName, "${dispatch.declaringClass.name}: 跳过未知来源弹窗失败", it)
                    }
            }
        })
    }

    /**
     * 去掉安装页上的「安全提醒」卡片（标题「安全提醒」+ 正文「该应用未经小米安全审核…」）。
     *
     * 卡片是 `FullSafeInstallHintViewObject` 这个列表项，标题/正文由安装器按未审核状态给出。
     * 这里在它绑定 ViewHolder 之后，只要标题或正文与「未审核」那两条文案一致，就把卡片根布局
     * 和整行高度都收掉（同款类还会用于「增强防护」「企业管控」提示，那些不动）。
     */
    private fun hideNotCheckedSafetyHint() {
        val clazz = findClassIfExists(HINT_VIEW_OBJECT)
        val holder = findClassIfExists("$HINT_VIEW_OBJECT\$ViewHolder")
        if (clazz == null || holder == null) {
            XposedLog.e(TAG, packageName, "$HINT_VIEW_OBJECT 不存在，跳过安全提醒卡片的隐藏")
            return
        }
        val bind = clazz.methods.firstOrNull {
            it.parameterCount == 1 && it.parameterTypes[0] == holder && it.returnType == Void.TYPE
        }
        if (bind == null) {
            XposedLog.e(TAG, packageName, "未找到 ${clazz.simpleName} 的 ViewHolder 绑定方法，跳过安全提醒卡片")
            return
        }
        hookMethod(bind, object : IMethodHook {
            override fun after(param: HookParam) {
                val viewHolder = param.args.getOrNull(0) ?: return
                val title = callMethod(viewHolder, "getTvTitle1") as? TextView ?: return
                val context = title.context ?: return
                val titleText = title.text?.toString().orEmpty()
                val contentText =
                    (callMethod(viewHolder, "getTvContent1") as? TextView)?.text?.toString().orEmpty()
                val matched = runCatching {
                    titleText == context.getString(STR_SAFETY_HINT_TITLE) ||
                        contentText == context.getString(STR_SAFETY_HINT_CONTENT)
                }.getOrDefault(false)
                if (!matched) return

                (callMethod(viewHolder, "getClRoot") as? View)?.visibility = View.GONE
                (viewHolder as? RecyclerView.ViewHolder)?.itemView?.let { item ->
                    item.visibility = View.GONE
                    item.layoutParams?.let { it.height = 0 }
                }
            }
        })
    }
}
