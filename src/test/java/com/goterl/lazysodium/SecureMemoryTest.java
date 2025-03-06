/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.sun.jna.Pointer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SecureMemoryTest extends BaseTest {


    @Test
    public void memZero() {
        byte[] b = new byte[]{4, 2, 2, 1};
        lazySodium.sodiumMemZero(b, b.length);
        assertTrue(isArrayFilledWith(b, 0));
    }

    @Test
    public void memZeroChecks() {
        byte[] b = new byte[10];
        assertThrows(IllegalArgumentException.class, () -> lazySodium.sodiumMemZero(b, -1));
        assertThrows(IllegalArgumentException.class, () -> lazySodium.sodiumMemZero(b, b.length + 1));
    }

    @Test
    public void mLock() {
        byte[] b = new byte[]{4, 5, 2, 1};
        boolean res = lazySodium.sodiumMLock(b, b.length);
        assertTrue(res);
        assertFalse(isArrayFilledWith(b, 0));
        boolean res2 = lazySodium.sodiumMUnlock(b, b.length);
        assertTrue(res2);
        assertTrue(isArrayFilledWith(b, 0));
    }

    @Test
    public void mallocAndFree() {
        for (int size : new int[]{0, 10, 100}) {
            Pointer ptr = lazySodium.sodiumMalloc(size);
            byte[] arr = ptr.getByteArray(0, size);
            assertTrue(isArrayFilledWith(arr, 0xDB));
            lazySodium.sodiumFree(ptr);
        }
    }

    @Test
    public void allocArrayAndFree() {
        for (int size : new int[]{0, 10, 100}) {
            for (int count : new int[]{0, 3, 5}) {
                Pointer ptr = lazySodium.sodiumAllocArray(count, size);
                byte[] arr = ptr.getByteArray(0, size * count);
                assertTrue(isArrayFilledWith(arr, 0xDB));
                lazySodium.sodiumFree(ptr);
            }
        }
    }

    @Test
    public void refuseInvalidMallocSize() {
        assertThrows(IllegalArgumentException.class, () -> lazySodium.sodiumMalloc(-1));
        assertThrows(IllegalArgumentException.class, () -> lazySodium.sodiumAllocArray(-1, 10));
        assertThrows(IllegalArgumentException.class, () -> lazySodium.sodiumAllocArray(10, -1));
    }

    // mprotect not tested, might clobber the JVM

    private boolean isArrayFilledWith(byte[] arr, int expectedValue) {
        byte expectedByte = (byte) expectedValue;
        for (byte b : arr) {
            if (b != expectedByte) {
                return false;
            }
        }
        return true;
    }


}
