/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.utils.LibraryLoader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class BaseTest {

    public static LazySodiumJava lazySodium;

    protected static int countZeros(byte[] buff) {
        int zeroes = 0;
        for (byte b : buff) {
            if (b == 0) {
                ++zeroes;
            }
        }
        return zeroes;
    }

    @BeforeAll
    public void doBeforeEverything() {
        lazySodium = SodiumHolder.lazySodium;
    }

    /**
     * Singleton, global holder for LazySodium instance, so that the library is not loaded multiple times, once for
     * each test class
     */
    private static class SodiumHolder {
        static final LazySodiumJava lazySodium = new LazySodiumJava(new SodiumJava(LibraryLoader.Mode.BUNDLED_ONLY));

        private SodiumHolder() {
        }
    }
}
