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

package com.sevtinge.hyperceiler.libhook.rules.community;

import static com.sevtinge.hyperceiler.libhook.BuildConfig.APP_MODULE_ID;

import com.sevtinge.hyperceiler.libhook.base.BaseHook;
import io.github.lingqiqi5211.ezhooktool.xposed.java.IMethodHook;
import com.sevtinge.hyperceiler.libhook.utils.hookapi.dexkit.IDexKit;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.result.MethodData;
import org.luckypray.dexkit.result.base.BaseData;

import java.lang.reflect.Method;

import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam;

public class FuckDetection extends BaseHook {
    private Method mGetPackageVersionName;

    @Override
    protected boolean useDexKit() {
        return true;
    }

    /**
     * HyperOS 4（小米社区）里两个锚点都已经不存在，本规则目前必然失配、由框架打 E：
     * - "binding.editContactInformation.text" 这个 databinding 串已从 dex 里删除；
     * - "5577218" 仍在，但只出现在反馈表单相关方法里
     * （FeedBackActivity#z1 拼 {"topicId":"5577218"}、PublishActivity#<clinit>、
     *   PublishFeedbackFragment#initView、PublishViewModel#X），
     * 全 dex 里也没有任何方法同时引用这两个串。
     * 另外本规则真正想拦的是「以 com.sevtinge.hyperceiler 包名判断模块」的检测，
     * 而该包名字符串在当前版本的小米社区里已经完全不存在（只剩
     * com.xiaomi.verificationsdk.internal.SensorHelper#D 里的
     * "de.robv.android.xposed.installer" 风控检测，与本规则无关）。
     * 也就是说目标检测方法已无迹可循，无法凭空重构——保持 requiredMember 如实报 E，
     * 不猜测 hook 点（猜错会把无关方法的入参置 null，属于真实破坏）。
     */
    @Override
    protected boolean initDexKit() {
        mGetPackageVersionName = requiredMember("GetPackageVersionName", new IDexKit() {
            @Override
            public BaseData dexkit(DexKitBridge bridge) throws ReflectiveOperationException {
                MethodData methodData = bridge.findMethod(FindMethod.create()
                        .matcher(MethodMatcher.create()
                                .usingStrings("5577218", "binding.editContactInformation.text")
                        )).singleOrNull();
                return methodData;
            }
        });
        return true;
    }

    @Override
    public void init() {
        hookMethod(mGetPackageVersionName, new IMethodHook() {
            @Override
            public void before(HookParam param) {
                if (param.getArgs()[0].equals(APP_MODULE_ID)) param.getArgs()[0] = null;
            }
        });
    }
}
