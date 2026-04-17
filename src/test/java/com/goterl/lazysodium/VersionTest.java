/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class VersionTest extends BaseTest {

    @Test
    public void hasBundledCorrectVersion() {
        String versionString = lazySodium.sodiumVersionString();
        int versionMajor = lazySodium.sodiumVersionMajor();
        int versionMinor = lazySodium.sodiumVersionMinor();
        boolean minimal = lazySodium.sodiumLibraryMinimal();
        assertEquals("1.0.22", versionString);
        assertEquals(26, versionMajor);
        assertEquals(4, versionMinor);
        assertFalse(minimal);
    }
}
