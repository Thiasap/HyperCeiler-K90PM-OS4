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

import android.view.View
import com.sevtinge.hyperceiler.common.log.XposedLog
import com.sevtinge.hyperceiler.libhook.base.BaseHook
import io.github.lingqiqi5211.ezhooktool.core.findMethod
import io.github.lingqiqi5211.ezhooktool.core.loadClass
import io.github.lingqiqi5211.ezhooktool.xposed.dsl.createHook
import org.luckypray.dexkit.query.enums.StringMatchType
import java.lang.reflect.Method

object LockOneHundredPoints : BaseHook() {
    override fun useDexKit() = true

    override fun initDexKit(): Boolean {
        scoreOld
        score
        score3
        addRiskApps
        return true
    }
    private val scoreOld by lazy<Method> {
        requiredMember("LockOneHundredPoints1") {
            it.findClass {
                matcher {
                    className = "com.miui.securityscan.scanner.ScoreManager"
                }
            }.findMethod {
                matcher {
                    addUsingString("getMinusPredictScore", StringMatchType.Contains)
                    returnType = "int"
                }
            }.single()
        }
    }

    private val score by lazy<Method> {
        requiredMember("LockOneHundredPoints2") {
            it.findClass {
                matcher {
                    className = "com.miui.securityscan.scanner.ScoreManager"
                }
            }.findMethod {
                matcher {
                    usingNumbers(41, 100, 0)
                    returnType = "int"
                }
            }.single()
        }
    }

    private val score3 by lazy<Method> {
        requiredMember("LockOneHundredPointsField") {
            it.findClass {
                matcher {
                    className = "com.miui.securityscan.scanner.ScoreManager"
                }
            }.findMethod {
                matcher {
                    addUsingField {
                        type = "java.util.Map"
                    }
                    addInvoke {
                        addUsingField {
                            type = "int"
                        }
                        returnType = "int"
                    }
                }
            }.single()
        }
    }

    /**
     * OS4 的 ScoreManager 已被完全混淆，原来「1 参 + 返回 void + 调用 TextUtils.isEmpty」
     * 的条件现在会同时命中「加入风险应用」和「移除风险应用」两个方法，
     * 因此不再用 .single()，而是把命中的方法全部 hook —— 两个方向都置空语义等价。
     */
    private val addRiskApps by lazy<List<Method>> {
        requiredMemberList("AddRiskApp") {
            it.findClass {
                matcher {
                    className = "com.miui.securityscan.scanner.ScoreManager"
                }
            }.findMethod {
                matcher {
                    addInvoke("Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z")
                    paramCount = 1
                    returnType = "void"
                }
            }
        }
    }

    override fun init() {
        loadClass("com.miui.securityscan.ui.main.MainContentFrame").findMethod { name("onClick"); parameterTypes(View::class.java) }.createHook {
                returnConstant(null)
            }

        runCatching {
            scoreOld.createHook {
                returnConstant(0)
            }
            score.createHook {
                returnConstant(100)
            }
            score3.createHook {
                returnConstant(true)
            }
            addRiskApps.forEach { method ->
                method.createHook {
                    returnConstant(null)
                }
            }
        }.onFailure {
            XposedLog.e(TAG, lpparam.packageName, "LockOneHundredPoints hook Failed: $it")
        }
    }
}

