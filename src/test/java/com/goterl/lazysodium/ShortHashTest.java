/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.ShortHash;
import com.goterl.lazysodium.utils.Key;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ShortHashTest extends BaseTest {

    private static final String HASHED_MESSAGE = "This should get hashed";
    private static final String CORRECT_MESSAGE_HASH = "9B680E20E9486A40";

    private ShortHash.Lazy shortHashLazy;
    private ShortHash.Native shortHashNative;

    @BeforeAll
    public void before() {
        shortHashLazy = lazySodium;
        shortHashNative = lazySodium;
    }

    @Test
    public void cryptoShortHashKeygen() {
        Key key = shortHashLazy.cryptoShortHashKeygen();
        assertNotNull(key);
        assertEquals(ShortHash.KEYBYTES, key.getAsBytes().length);

        byte[] keyBytes = new byte[ShortHash.KEYBYTES];
        shortHashNative.cryptoShortHashKeygen(keyBytes);
    }

    @Test
    public void rejectShortKeyBuffer() {
        assertThrows(IllegalArgumentException.class, () -> shortHashNative.cryptoShortHashKeygen(new byte[ShortHash.KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> shortHashNative.cryptoShortHashKeygen(new byte[ShortHash.KEYBYTES + 1]));
    }

    @Test
    public void cryptoShortHashStr() throws SodiumException {
        Key key = Key.fromBytes(new byte[ShortHash.KEYBYTES]);
        String hashFromString = shortHashLazy.cryptoShortHashStr(HASHED_MESSAGE, key);
        assertEquals(CORRECT_MESSAGE_HASH, hashFromString);
    }

    @Test
    public void cryptoShortHashHex() throws SodiumException {
        Key key = Key.fromBytes(new byte[ShortHash.KEYBYTES]);
        String hashFromHex = shortHashLazy.cryptoShortHashHex(lazySodium.toHexStr(HASHED_MESSAGE.getBytes(StandardCharsets.UTF_8)), key);
        assertEquals(CORRECT_MESSAGE_HASH, hashFromHex);
    }

    @Test
    public void cryptoShortHash() throws SodiumException {
        Key key = Key.fromBytes(new byte[ShortHash.KEYBYTES]);
        String hashFromBytes = shortHashLazy.cryptoShortHash(HASHED_MESSAGE.getBytes(StandardCharsets.UTF_8), key);
        assertEquals(CORRECT_MESSAGE_HASH, hashFromBytes);
    }

    @Test
    public void cryptoShortHashNative() {
        byte[] inBytes = HASHED_MESSAGE.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[ShortHash.BYTES];
        boolean result = shortHashNative.cryptoShortHash(out, inBytes, inBytes.length, new byte[ShortHash.KEYBYTES]);
        assertTrue(result);
        assertEquals(CORRECT_MESSAGE_HASH, lazySodium.toHexStr(out));
    }

    @Test
    public void hashChecks() {
        byte[] key = new byte[ShortHash.KEYBYTES - 1];
        assertThrows(IllegalArgumentException.class, () -> shortHashLazy.cryptoShortHash(HASHED_MESSAGE.getBytes(StandardCharsets.UTF_8), Key.fromBytes(key)));
        assertThrows(IllegalArgumentException.class, () -> shortHashLazy.cryptoShortHash(HASHED_MESSAGE.getBytes(StandardCharsets.UTF_8), Key.fromBytes(new byte[ShortHash.KEYBYTES + 1])));

        byte[] inBytes = HASHED_MESSAGE.getBytes(StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class, () -> shortHashNative.cryptoShortHash(new byte[ShortHash.BYTES - 1], inBytes, inBytes.length, key));
        assertThrows(IllegalArgumentException.class, () -> shortHashNative.cryptoShortHash(new byte[ShortHash.BYTES + 1], inBytes, inBytes.length, key));
        byte[] out = new byte[ShortHash.BYTES];
        assertThrows(IllegalArgumentException.class, () -> shortHashNative.cryptoShortHash(out, inBytes, inBytes.length + 1, key));
        assertThrows(IllegalArgumentException.class, () -> shortHashNative.cryptoShortHash(out, inBytes, inBytes.length, new byte[ShortHash.KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> shortHashNative.cryptoShortHash(out, inBytes, inBytes.length, new byte[ShortHash.KEYBYTES + 1]));
    }

}
