/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.utils;

import com.sun.jna.NativeLong;

public class BaseChecker {

    public static void checkBetween(String name, long num, long min, long max) {
        if (num < min) {
            throw new IllegalArgumentException("Provided " + name + " is below minimum bound.");
        }
        if (num > max) {
            throw new IllegalArgumentException("Provided " + name + " is above maximum bound.");
        }
    }

    public static void checkBetween(String name, NativeLong num, NativeLong min, NativeLong max) {
        checkBetween(name, num.longValue(), min.longValue(), max.longValue());
    }

    public static void checkAtLeast(String name, long num, long min) {
        if (num < min) {
            throw new IllegalArgumentException("Provided " + name + " is below minimum bound.");
        }
    }

    public static boolean isBetween(long num, long min, long max) {
        return min <= num && num <= max;
    }

    public static boolean correctLen(long num, long len) {
        return num == len;
    }

    /**
     * Throw if provided value does not match an expected value.
     */
    public static void checkEqual(String name, int actual, int expected) {
        if (actual != expected) {
            // Neither value is reported, in case this is passed sensitive
            // values, even though most uses are likely for header lengths and
            // similar.
            throw new IllegalArgumentException(
                "Provided " + name + " did not match expected value");
        }
    }

    public static void checkExpectedMemorySize(String name, int actual, int expected) {
        checkEqual(name, expected, actual);
    }

    public static void checkArrayLength(String name, byte[] array, int length) {
        checkArrayLength(name, array.length, length);
    }

    public static void checkOptionalArrayLength(String name, byte[] array, int length) {
        if (array == null) {
            if (length != 0) {
                throw new IllegalArgumentException("Provided non-zero length for null " + name);
            }
        } else {
            checkArrayLength(name, array.length, length);
        }
    }

    private static void checkArrayLength(String name, int arrayLength, int length) {
        if (length > arrayLength) {
            throw new IllegalArgumentException("Provided " + name + " array length is larger than array");
        }
        if (length < 0) {
            throw new IllegalArgumentException("Provided " + name + " array length is negative");
        }
    }

    public static void checkOptionalOutPointer(String name, byte[] refArray) {
        if (refArray != null && refArray.length == 0) {
            throw new IllegalArgumentException("Provided " + name + " must be either null or non-empty");
        }
    }

    public static void checkOptionalOutPointer(String name, long[] refArray) {
        if (refArray != null && refArray.length == 0) {
            throw new IllegalArgumentException("Provided " + name + " must be either null or non-empty");
        }
    }

    public static void requireNonNull(String name, Object state) {
        if (state == null) {
            throw new IllegalArgumentException("Provided " + name + " must not be null");
        }
    }
}
