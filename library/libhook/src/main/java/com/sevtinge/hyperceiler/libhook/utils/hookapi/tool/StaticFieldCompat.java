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
 *
 * Copyright (C) 2023-2026 HyperCeiler Contributions
 */
package com.sevtinge.hyperceiler.libhook.utils.hookapi.tool;

import androidx.annotation.Nullable;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * 静态 final 字段写入兼容层。
 * <p>
 * 从 Android 14 起 ART 在 {@link Field#set(Object, Object)} 里直接拒绝写
 * {@code static final} 字段（IllegalAccessException: Cannot set private static final field），
 * 所以像 {@code MiuiVpnEditFragment.VPN_TYPES} 这种字段无法再用常规反射覆盖。
 * <p>
 * 这里用 {@code sun.misc.Unsafe} 的 staticFieldBase/staticFieldOffset 直接改内存，
 * 作为规则里「反射失败后的兜底」，不改动原有逻辑。
 * <p>
 * 所有入口都不抛异常，只返回是否成功；拿不到 Unsafe 时静默降级。
 */
public final class StaticFieldCompat {

    private static final Object UNSAFE;
    private static final Method STATIC_FIELD_BASE;
    private static final Method STATIC_FIELD_OFFSET;
    private static final Method PUT_OBJECT;

    static {
        Object unsafe = null;
        Method base = null;
        Method offset = null;
        Method put = null;
        for (String className : new String[]{"sun.misc.Unsafe", "jdk.internal.misc.Unsafe"}) {
            try {
                Class<?> unsafeClass = Class.forName(className);
                Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");
                theUnsafe.setAccessible(true);
                unsafe = theUnsafe.get(null);
                base = unsafeClass.getMethod("staticFieldBase", Field.class);
                offset = unsafeClass.getMethod("staticFieldOffset", Field.class);
                put = unsafeClass.getMethod("putObject", Object.class, long.class, Object.class);
                break;
            } catch (Throwable ignored) {
                // 尝试下一个实现
            }
        }
        UNSAFE = unsafe;
        STATIC_FIELD_BASE = base;
        STATIC_FIELD_OFFSET = offset;
        PUT_OBJECT = put;
    }

    private StaticFieldCompat() {
    }

    public static boolean isAvailable() {
        return UNSAFE != null && STATIC_FIELD_BASE != null
            && STATIC_FIELD_OFFSET != null && PUT_OBJECT != null;
    }

    /**
     * 写入静态字段（含 static final）。
     *
     * @return true 表示写入成功；false 表示字段不存在或当前环境不支持
     */
    public static boolean setStaticObject(@Nullable Class<?> clazz, String fieldName, Object value) {
        if (clazz == null || !isAvailable()) return false;
        try {
            Field field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
            Object base = STATIC_FIELD_BASE.invoke(UNSAFE, field);
            long offset = (Long) STATIC_FIELD_OFFSET.invoke(UNSAFE, field);
            PUT_OBJECT.invoke(UNSAFE, base, offset, value);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }
}
