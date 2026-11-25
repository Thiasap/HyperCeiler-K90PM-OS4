/*
 * This file is part of HyperCeiler.
 *
 * HyperCeiler is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2023-2026 HyperCeiler Contributions
 */
package com.sevtinge.hyperceiler.libhook.rules.systemframework.others

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.ResolveInfo
import android.os.Bundle
import android.os.PowerExemptionManager
import com.sevtinge.hyperceiler.common.log.XposedLog
import com.sevtinge.hyperceiler.libhook.base.BaseHook
import io.github.lingqiqi5211.ezhooktool.core.findField
import io.github.lingqiqi5211.ezhooktool.core.findMethod
import io.github.lingqiqi5211.ezhooktool.xposed.dsl.createInterceptHook
import io.github.lingqiqi5211.ezhooktool.xposed.dsl.interceptHookMethod
import io.github.lingqiqi5211.ezhooktool.xposed.java.Deoptimizers

/**
 * Source:
 * https://github.com/Howard20181/HyperOS_FCM_Live/blob/main/HyperFCMLive/src/main/java/io/github/howard20181/hyperos/fcmlive/Hooker.java
 */
object GMSDozeFixFramework : BaseHook() {
    private val cnDeferBroadcast = setOf(
        "com.google.android.intent.action.GCM_RECONNECT",
        "com.google.android.gcm.DISCONNECTED",
        "com.google.android.gcm.CONNECTED",
        "com.google.android.gms.gcm.HEARTBEAT_ALARM"
    )
    private const val GMS_PACKAGE_NAME = "com.google.android.gms"
    private const val GMS_PERSISTENT_PROCESS_NAME = "com.google.android.gms.persistent"
    private const val ACTION_REMOTE_INTENT = "com.google.android.c2dm.intent.RECEIVE"

    private var powerExemptionManager: PowerExemptionManager? = null

    private fun getPowerExemptionManager(context: Context): PowerExemptionManager {
        if (powerExemptionManager == null) {
            powerExemptionManager = PowerExemptionManager(context)
        }
        return powerExemptionManager!!
    }

    override fun init() {
        val greezeManagerServiceClass =
            findClassIfExists("com.miui.server.greeze.GreezeManagerService")

        val domesticPolicyManagerClass =
            findClassIfExists("com.miui.server.greeze.DomesticPolicyManager")

        val listAppsManagerClass = findClassIfExists("com.miui.server.greeze.power.ListAppsManager")

        val awareResourceControlClass =
            findClassIfExists("com.miui.server.greeze.power.AwareResourceControl")

        val broadcastQueueModernStubImplClass =
            findClassIfExists("com.android.server.am.BroadcastQueueModernStubImpl")

        val broadcastQueueClass = findClassIfExists("com.android.server.am.BroadcastQueue")
        val broadcastRecordClass = findClassIfExists("com.android.server.am.BroadcastRecord")
        val processPolicyClass = findClassIfExists("com.android.server.am.ProcessPolicy")
        val activityManagerServiceClass =
            findClassIfExists("com.android.server.am.ActivityManagerService")

        hookGreezeManagerService(greezeManagerServiceClass)
        hookDomesticPolicyManager(domesticPolicyManagerClass)
        hookListAppsManager(listAppsManagerClass)
        hookBroadcastQueueModernStubImpl(
            broadcastQueueModernStubImplClass, broadcastQueueClass, broadcastRecordClass
        )
        hookProcessPolicy(processPolicyClass)
        hookAwareResourceControl(awareResourceControlClass)
        hookActivityManagerService(activityManagerServiceClass)
    }

    private fun hookGreezeManagerService(clazz: Class<*>?) {
        clazz ?: return
        try {
            val getPackageNameFromUidMethod = clazz.getDeclaredMethod(
                "getPackageNameFromUid", Int::class.java
            )
            getPackageNameFromUidMethod.isAccessible = true
            clazz.interceptHookMethod(
                "isAllowBroadcast",
                Int::class.java,
                String::class.java,
                Int::class.java,
                String::class.java,
                String::class.java
            ) { chain ->
                var calleePkgName = chain.getArg(3) as? String
                try {
                    val calleeUid = chain.getArg(2) as? Int
                    if (calleeUid != null) {
                        val resolved = com.sevtinge.hyperceiler.libhook.base.BaseHook.invokeOriginalMethod(
                            getPackageNameFromUidMethod, chain.thisObject, calleeUid
                        ) as? String
                        if (resolved != null) {
                            calleePkgName = resolved
                        }
                    }
                } catch (e: Exception) {
                    XposedLog.e(TAG, packageName, "Failed to get callee package name", e)
                }
                val action = chain.getArg(4) as? String
                if (action != null) {
                    val callerPkgName = chain.getArg(1) as? String
                    if ((callerPkgName == GMS_PACKAGE_NAME && action == ACTION_REMOTE_INTENT) ||
                        ((calleePkgName == GMS_PACKAGE_NAME || calleePkgName == GMS_PERSISTENT_PROCESS_NAME) &&
                            action in cnDeferBroadcast)
                    ) {
                        return@interceptHookMethod true
                    }
                }
                chain.proceed()
            }
            clazz.getDeclaredMethod(
                "isAllowBroadcast",
                Int::class.java,
                String::class.java,
                Int::class.java,
                String::class.java,
                String::class.java
            ).let(Deoptimizers::deoptimize)
        } catch (e: Exception) {
            XposedLog.e(TAG, packageName, "Hook Failed in isAllowBroadcast: ", e)
        }

        try {
            clazz.interceptHookMethod(
                "deferBroadcastForMiui",
                String::class.java
            ) { chain ->
                val action = chain.getArg(0) as? String ?: return@interceptHookMethod chain.proceed()
                if (action in cnDeferBroadcast) {
                    return@interceptHookMethod false
                }
                chain.proceed()
            }
            clazz.getDeclaredMethod(
                "deferBroadcastForMiui",
                String::class.java
            ).let(Deoptimizers::deoptimize)
        } catch (e: Exception) {
            XposedLog.e(TAG, packageName, "Hook Failed in deferBroadcastForMiui: ", e)
        }

        try {
            val triggerGmsLimitActionMethod = clazz.findMethod {
                name("triggerGMSLimitAction")
            }
            triggerGmsLimitActionMethod.createInterceptHook { chain ->
                val methodArgs = chain.args.toMutableList()
                if (methodArgs.isNotEmpty()) {
                    methodArgs[0] = false
                    chain.proceed(methodArgs.toTypedArray())
                } else {
                    setBooleanField(chain.thisObject, "mGmsLimitEnabled", false)
                    chain.proceed()
                }
            }
            Deoptimizers.deoptimize(triggerGmsLimitActionMethod)
        } catch (e: Exception) {
            XposedLog.e(TAG, packageName, "Hook Failed in triggerGMSLimitAction: ", e)
        }
    }

    private fun hookDomesticPolicyManager(clazz: Class<*>?) {
        clazz ?: return
        try {
            clazz.interceptHookMethod(
                "deferBroadcast",
                String::class.java
            ) {
                false
            }
            clazz.getDeclaredMethod(
                "deferBroadcast",
                String::class.java
            ).let(Deoptimizers::deoptimize)
        } catch (e: Exception) {
            XposedLog.e(TAG, packageName, "Hook Failed in deferBroadcast: ", e)
        }
    }

    /**
     * GMS 加入「休眠仍然允许联网」白名单，并从系统黑名单里摘出来。
     *
     * 4.0.8.0（OS4.0.8）把 ListAppsManager 的两个字段从实例字段改成了静态字段：
     *   旧：{@code mSystemBlackList} / {@code mUseDataWhiteList}（实例，构造器里初始化）
     *   新：{@code SYSTEM_BLACK_LIST}（public static List）/ {@code USE_DATA_WHITE_LIST}
     *       （private static Set，另有 public static getUseDataWhiteList()）
     * 旧写法在 4.0.8 上必抛 NoSuchFieldException（设备日志：Hook Failed in isInWhiteList /
     * Failed to modify mSystemBlackList，每次开机两条 E）。这里按「新字段优先、旧字段兜底」
     * 解析一次，解析结果缓存成 lambda 里的局部引用，避免每次调用反射查找。
     * 两个字段都没有时打 E，不静默。
     */
    private fun hookListAppsManager(clazz: Class<*>?) {
        clazz ?: return

        // ---- 白名单集合：新静态 getter/字段 → 旧实例字段 ----
        val staticWhiteList: MutableSet<String>? = runCatching {
            clazz.getDeclaredMethod("getUseDataWhiteList").apply { isAccessible = true }
                .invoke(null) as? MutableSet<String>
        }.getOrNull() ?: runCatching {
            clazz.getDeclaredField("USE_DATA_WHITE_LIST").apply { isAccessible = true }
                .get(null) as? MutableSet<String>
        }.getOrNull()

        val instanceWhiteField = clazz.declaredFields.firstOrNull { it.name == "mUseDataWhiteList" }
            ?.apply { isAccessible = true }

        // ---- 系统黑名单：新静态字段 → 旧实例字段 ----
        val staticBlackList: MutableCollection<Any?>? = runCatching {
            clazz.getDeclaredField("SYSTEM_BLACK_LIST").apply { isAccessible = true }
                .get(null) as? MutableCollection<Any?>
        }.getOrNull()

        val instanceBlackField = clazz.declaredFields.firstOrNull { it.name == "mSystemBlackList" }
            ?.apply { isAccessible = true }

        if (staticWhiteList == null && instanceWhiteField == null) {
            XposedLog.e(TAG, packageName,
                "USE_DATA_WHITE_LIST / mUseDataWhiteList 都不存在，GMS 没有被加进休眠白名单")
        }
        if (staticBlackList == null && instanceBlackField == null) {
            XposedLog.e(TAG, packageName,
                "SYSTEM_BLACK_LIST / mSystemBlackList 都不存在，GMS 无法从系统黑名单摘除")
        }
        XposedLog.d(TAG, packageName,
            "ListAppsManager fields: whiteList(static/instance)=" +
                "${staticWhiteList != null}/${instanceWhiteField != null}, blackList(static/instance)=" +
                "${staticBlackList != null}/${instanceBlackField != null}")

        // 静态字段现在就改一次；之后每次 isInWhiteList / isIncludeSystemBlack 再兜一次，
        // 因为云端配置（dealCloudWhiteList）会 clear+重建这些集合。
        staticBlackList?.remove(GMS_PACKAGE_NAME)
        staticWhiteList?.add(GMS_PACKAGE_NAME)

        if (instanceBlackField != null) {
            try {
                chainAllConstructors(clazz) { chain ->
                    val result = chain.proceed()
                    try {
                        val thisObject = chain.thisObject ?: return@chainAllConstructors result
                        (instanceBlackField.get(thisObject) as? MutableCollection<Any?>)
                            ?.remove(GMS_PACKAGE_NAME)
                    } catch (e: Exception) {
                        XposedLog.e(TAG, packageName, "Failed to modify mSystemBlackList", e)
                    }
                    result
                }
                clazz.declaredConstructors.forEach { constructor ->
                    Deoptimizers.deoptimize(constructor)
                }
            } catch (e: Exception) {
                XposedLog.e(TAG, packageName, "Hook Failed in ListAppsManager constructor", e)
            }
        }

        try {
            val isInWhiteListMethod = clazz.declaredMethods.firstOrNull {
                it.name == "isInWhiteList" && it.parameterCount == 1 &&
                    it.parameterTypes[0] == String::class.java
            } ?: throw NoSuchMethodException("isInWhiteList(String)")
            isInWhiteListMethod.createInterceptHook { chain ->
                try {
                    val target = chain.getArg(0) as? String
                    if (target == GMS_PACKAGE_NAME) {
                        // 白名单集合能拿到就顺手补进去（多处会被直接读），
                        // 但这个方法的返回值才是冻结判定的唯一依据，所以直接放行。
                        staticWhiteList?.add(GMS_PACKAGE_NAME)
                        instanceWhiteField?.let { field ->
                            (field.get(chain.thisObject) as? MutableSet<String>)
                                ?.add(GMS_PACKAGE_NAME)
                        }
                        return@createInterceptHook true
                    }
                    instanceWhiteField?.let { field ->
                        (field.get(chain.thisObject) as? MutableSet<String>)
                            ?.add(GMS_PACKAGE_NAME)
                    }
                } catch (e: Exception) {
                    XposedLog.e(TAG, packageName, "Failed to modify mUseDataWhiteList", e)
                }
                chain.proceed()
            }
            Deoptimizers.deoptimize(isInWhiteListMethod)
        } catch (e: Exception) {
            XposedLog.e(TAG, packageName, "Hook Failed in isInWhiteList", e)
        }
    }

    private fun hookBroadcastQueueModernStubImpl(
        clazz: Class<*>?,
        broadcastQueueClass: Class<*>?,
        broadcastRecordClass: Class<*>?
    ) {
        if (clazz == null || broadcastQueueClass == null || broadcastRecordClass == null) return
        try {
            clazz.interceptHookMethod(
                "checkApplicationAutoStart",
                broadcastQueueClass,
                broadcastRecordClass,
                ResolveInfo::class.java
            ) { chain ->
                try {
                    val broadcastRecord = chain.getArg(1) ?: return@interceptHookMethod chain.proceed()
                    val callerPackage = getObjectField(broadcastRecord, "callerPackage") as? String
                        ?: return@interceptHookMethod chain.proceed()
                    val intent = getObjectField(broadcastRecord, "intent") as? Intent
                        ?: return@interceptHookMethod chain.proceed()
                    if (callerPackage == GMS_PACKAGE_NAME && intent.action == ACTION_REMOTE_INTENT) {
                        return@interceptHookMethod true
                    }
                } catch (e: Exception) {
                    XposedLog.e(TAG, packageName, "Failed to modify checkApplicationAutoStart", e)
                }
                chain.proceed()
            }
            clazz.getDeclaredMethod(
                "checkApplicationAutoStart",
                broadcastQueueClass,
                broadcastRecordClass,
                ResolveInfo::class.java
            ).let(Deoptimizers::deoptimize)
        } catch (e: Exception) {
            XposedLog.e(TAG, packageName, "Hook Failed in checkApplicationAutoStart", e)
        }
    }

    private fun hookProcessPolicy(clazz: Class<*>?) {
        clazz ?: return
        try {
            clazz.interceptHookMethod(
                "getWhiteList",
                Int::class.java
            ) { chain ->
                val result = chain.proceed()
                try {
                    val flags = chain.getArg(0) as? Int ?: return@interceptHookMethod result
                    if ((flags and 1) == 0) return@interceptHookMethod result

                    val list = when (result) {
                        is MutableList<*> -> result as MutableList<Any?>
                        is List<*> -> result.toMutableList()
                        else -> return@interceptHookMethod result
                    }

                    if (!list.contains(GMS_PACKAGE_NAME)) list.add(GMS_PACKAGE_NAME)
                    if (!list.contains(GMS_PERSISTENT_PROCESS_NAME)) list.add(
                        GMS_PERSISTENT_PROCESS_NAME
                    )
                    list
                } catch (e: Exception) {
                    XposedLog.e(TAG, packageName, "Failed to modify getWhiteList", e)
                    result
                }
            }
        } catch (e: Exception) {
            XposedLog.e(TAG, packageName, "Hook Failed in getWhiteList", e)
        }
    }

    private fun hookAwareResourceControl(clazz: Class<*>?) {
        clazz ?: return
        try {
            chainAllConstructors(clazz) { chain ->
                val result = chain.proceed()
                try {
                    val thisObject = chain.thisObject ?: return@chainAllConstructors result
                    val noNetworkBlackUids = getObjectField(thisObject, "mNoNetworkBlackUids")
                        as? MutableCollection<Any?>
                        ?: return@chainAllConstructors result
                    noNetworkBlackUids.remove(GMS_PACKAGE_NAME)
                } catch (e: Exception) {
                    XposedLog.e(TAG, packageName, "Failed to modify mNoNetworkBlackUids", e)
                }
                result
            }
            clazz.declaredConstructors.forEach { constructor ->
                Deoptimizers.deoptimize(constructor)
            }
        } catch (e: Exception) {
            XposedLog.e(TAG, packageName, "Hook Failed in AwareResourceControl constructor", e)
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun hookActivityManagerService(clazz: Class<*>?) {
        clazz ?: return
        try {
            val mContextField = clazz.getDeclaredField("mContext")
            mContextField.isAccessible = true

            val iApplicationThreadClass =
                findClassIfExists("android.app.IApplicationThread") ?: return
            val iIntentReceiverClass =
                findClassIfExists("android.content.IIntentReceiver") ?: return
            val processRecordClass =
                findClassIfExists("com.android.server.am.ProcessRecord") ?: return
            val infoField = processRecordClass.getDeclaredField("info")
            infoField.isAccessible = true

            val getRecordMethod =
                clazz.getDeclaredMethod("getRecordForAppLOSP", iApplicationThreadClass)

            // broadcastIntentWithFeature (TIRAMISU+ / API 33+, 16 params)
            val intentArgIndex = 2
            val broadcastMethod = clazz.getDeclaredMethod(
                "broadcastIntentWithFeature",
                iApplicationThreadClass, String::class.java,
                Intent::class.java, String::class.java, iIntentReceiverClass,
                Int::class.java, String::class.java, Bundle::class.java,
                Array<String>::class.java, Array<String>::class.java,
                Array<String>::class.java, Int::class.java, Bundle::class.java,
                Boolean::class.java, Boolean::class.java, Int::class.java
            )

            chain(broadcastMethod) { chain ->
                val intent = chain.getArg(intentArgIndex) as? Intent
                if (intent != null && ACTION_REMOTE_INTENT == intent.action) {
                    val app = com.sevtinge.hyperceiler.libhook.base.BaseHook.invokeOriginalMethod(
                        getRecordMethod, chain.thisObject, chain.getArg(0)
                    )
                    if (app != null) {
                        val info = infoField.get(app) as? ApplicationInfo
                        if (info != null && GMS_PACKAGE_NAME == info.packageName) {
                            val targetPackage = intent.`package`
                            val mContext = mContextField.get(chain.thisObject) as? Context
                            if (targetPackage != null && mContext != null) {
                                getPowerExemptionManager(mContext).addToTemporaryAllowList(
                                    targetPackage,
                                    102, // PowerExemptionManager.REASON_PUSH_MESSAGING_OVER_QUOTA
                                    "GOOGLE_C2DM",
                                    2000
                                )
                            }
                            if ((intent.flags and Intent.FLAG_INCLUDE_STOPPED_PACKAGES) == 0) {
                                intent.addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
                            }
                        }
                    }
                }
                chain.proceed()
            }
            Deoptimizers.deoptimize(broadcastMethod)
        } catch (e: Exception) {
            XposedLog.e(TAG, packageName, "Hook Failed in ActivityManagerService", e)
        }
    }
}
