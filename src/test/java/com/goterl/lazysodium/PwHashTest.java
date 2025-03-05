/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.PwHash;
import com.sun.jna.NativeLong;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PwHashTest extends BaseTest {

    private final String PASSWORD = "Password123456!!!!@@";
    private final byte[] PASSWORD_BYTES = PASSWORD.getBytes(StandardCharsets.UTF_8);
    private PwHash.Lazy pwHashLazy;
    private PwHash.Native pwHashNative;

    @BeforeAll
    public void before() {
        pwHashLazy = lazySodium;
        pwHashNative = lazySodium;
    }

    @Test
    public void cryptoPwHashOnString() throws SodiumException {
        String output = pwHashLazy.cryptoPwHash(
                PASSWORD,
                PwHash.BYTES_MIN,
                new byte[PwHash.SALTBYTES],
                PwHash.OPSLIMIT_MIN,
                PwHash.MEMLIMIT_MIN,
                PwHash.Alg.getDefault()
        );

        assertEquals("1FD96CB6F0EDBF9B66AADDD3E0A8FD48", output);
    }

    @Test
    public void cryptoPwHashOnStringChecks() {
        final byte[] salt = new byte[PwHash.SALTBYTES];
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHash(PASSWORD, -1, new byte[PwHash.SALTBYTES - 1], PwHash.OPSLIMIT_MIN, PwHash.MEMLIMIT_MIN, PwHash.Alg.getDefault()));
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHash(PASSWORD, PwHash.BYTES_MIN - 1, new byte[PwHash.SALTBYTES - 1], PwHash.OPSLIMIT_MIN, PwHash.MEMLIMIT_MIN, PwHash.Alg.getDefault()));
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHash(PASSWORD, 300, new byte[PwHash.SALTBYTES - 1], PwHash.OPSLIMIT_MIN, PwHash.MEMLIMIT_MIN, PwHash.Alg.getDefault()));
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHash(PASSWORD, 300, salt, PwHash.OPSLIMIT_MIN - 1, PwHash.MEMLIMIT_MIN, PwHash.Alg.getDefault()));
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHash(PASSWORD, 300, salt, PwHash.OPSLIMIT_MAX + 1, PwHash.MEMLIMIT_MIN, PwHash.Alg.getDefault()));
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHash(PASSWORD, 300, salt, PwHash.OPSLIMIT_MIN, new NativeLong(PwHash.MEMLIMIT_MIN.longValue() - 1), PwHash.Alg.getDefault()));
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHash(PASSWORD, 300, salt, PwHash.OPSLIMIT_MIN, new NativeLong(PwHash.MEMLIMIT_MAX.longValue() + 1), PwHash.Alg.getDefault()));
    }

    @Test
    public void cryptoPwHashOnBytes() {
        byte[] salt = new byte[PwHash.SALTBYTES];
        byte[] hash = new byte[PwHash.BYTES_MIN];
        assertTrue(pwHashNative.cryptoPwHash(
                hash,
                hash.length,
                PASSWORD_BYTES,
                PASSWORD_BYTES.length,
                salt,
                PwHash.OPSLIMIT_MIN,
                PwHash.MEMLIMIT_MIN,
                PwHash.Alg.getDefault()
        ));

        assertArrayEquals(LazySodium.toBin("1FD96CB6F0EDBF9B66AADDD3E0A8FD48"), hash);
    }

    @Test
    public void cryptoPwHashOnBytesChecks() {
        final byte[] salt = new byte[PwHash.SALTBYTES];
        final byte[] hash = new byte[300];
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHash(hash, Integer.MIN_VALUE, PASSWORD_BYTES, PASSWORD_BYTES.length, new byte[PwHash.SALTBYTES - 1], PwHash.OPSLIMIT_MIN, PwHash.MEMLIMIT_MIN, PwHash.Alg.getDefault()));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHash(hash, PwHash.BYTES_MIN - 1, PASSWORD_BYTES, PASSWORD_BYTES.length, new byte[PwHash.SALTBYTES - 1], PwHash.OPSLIMIT_MIN, PwHash.MEMLIMIT_MIN, PwHash.Alg.getDefault()));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHash(hash, hash.length + 1, PASSWORD_BYTES, PASSWORD_BYTES.length, new byte[PwHash.SALTBYTES - 1], PwHash.OPSLIMIT_MIN, PwHash.MEMLIMIT_MIN, PwHash.Alg.getDefault()));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHash(hash, hash.length, PASSWORD_BYTES, PASSWORD_BYTES.length, new byte[PwHash.SALTBYTES - 1], PwHash.OPSLIMIT_MIN, PwHash.MEMLIMIT_MIN, PwHash.Alg.getDefault()));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHash(hash, hash.length, PASSWORD_BYTES, PASSWORD_BYTES.length, salt, PwHash.OPSLIMIT_MIN - 1, PwHash.MEMLIMIT_MIN, PwHash.Alg.getDefault()));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHash(hash, hash.length, PASSWORD_BYTES, PASSWORD_BYTES.length, salt, PwHash.OPSLIMIT_MAX + 1, PwHash.MEMLIMIT_MIN, PwHash.Alg.getDefault()));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHash(hash, hash.length, PASSWORD_BYTES, PASSWORD_BYTES.length, salt, PwHash.OPSLIMIT_MIN, new NativeLong(PwHash.MEMLIMIT_MIN.longValue() - 1), PwHash.Alg.getDefault()));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHash(hash, hash.length, PASSWORD_BYTES, PASSWORD_BYTES.length, salt, PwHash.OPSLIMIT_MIN, new NativeLong(PwHash.MEMLIMIT_MAX.longValue() + 1), PwHash.Alg.getDefault()));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHash(hash, hash.length, PASSWORD_BYTES, PASSWORD_BYTES.length + 1, salt, PwHash.OPSLIMIT_MIN, PwHash.MEMLIMIT_MIN, PwHash.Alg.getDefault()));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHash(hash, hash.length, PASSWORD_BYTES, Integer.MIN_VALUE, salt, PwHash.OPSLIMIT_MIN, PwHash.MEMLIMIT_MIN, PwHash.Alg.getDefault()));
    }

    @Test
    public void strMin() throws SodiumException {
        String hash = pwHashLazy.cryptoPwHashStr(
                PASSWORD,
                3,
                PwHash.MEMLIMIT_MIN
        );

        boolean isCorrect = pwHashLazy.cryptoPwHashStrVerify(hash, PASSWORD);

        assertTrue(isCorrect, "Minimum hashing failed.");
    }


    // We don't test for this as it's pretty demanding and
    // will fail on most machines
    public void cryptoPwHashStrTestSensitive() {
    }

}
