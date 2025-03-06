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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PwHashTest extends BaseTest {

    private static final String PASSWORD = "Password123456!!!!@@";
    private static final byte[] PASSWORD_BYTES = PASSWORD.getBytes(StandardCharsets.UTF_8);
    private static final String CORRECT_HASH = "$argon2id$v=19$m=256,t=2,p=1$XowEZ2ydqpE3lUnAKGtKgA$3DGEVywJs1mQ8hUy6RBdG6MyobzqgKdhwvxKm1D0Rao";
    private static final String CORRECT_HASH_HEX = "246172676F6E32696424763D3139246D3D382C743D332C703D3124542B55626E74677348626A3977787378475479464F51245669645A306A336E6D75316C6756746847306D636E50416232474778313361466A31552B4E4A614D566C34";
    private static final String CORRECT_HASH_HEX_WITH_ZERO = "246172676F6E32696424763D3139246D3D382C743D332C703D3124542B55626E74677348626A3977787378475479464F51245669645A306A336E6D75316C6756746847306D636E50416232474778313361466A31552B4E4A614D566C3400";
    private static final String CORRECT_HASH_HEX_WITH_ZEROES = "246172676F6E32696424763D3139246D3D382C743D332C703D3124542B55626E74677348626A3977787378475479464F51245669645A306A336E6D75316C6756746847306D636E50416232474778313361466A31552B4E4A614D566C340000000000000000000000000000000000000000000000000000000000000000000000";
    private static final byte[] CORRECT_HASH_BYTES = (CORRECT_HASH + '\u0000').getBytes(StandardCharsets.UTF_8);
    public static final String INVALID_TOO_LONG_HASH_HEX = new String(new char[PwHash.STR_BYTES * 2]).replace('\u0000', 'A');
    public static final String INVALID_TOO_LONG_HASH = new String(new char[PwHash.STR_BYTES]).replace('\u0000', 'x');
    public static final byte[] INVALID_TOO_LONG_HASH_BYTES = (INVALID_TOO_LONG_HASH + '\u0000').getBytes(StandardCharsets.UTF_8);
    private PwHash.Lazy pwHashLazy;
    private PwHash.Native pwHashNative;

    @BeforeAll
    public void before() {
        pwHashLazy = lazySodium;
        pwHashNative = lazySodium;
    }

    @Test
    public void cryptoPwHashLazy() throws SodiumException {
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
    public void cryptoPwHashLazyChecks() {
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
    public void cryptoPwHashNative() {
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
    public void cryptoPwHashNativeChecks() {
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
    public void cryptoPwHashStrNative() {
        byte[] outputStr = new byte[PwHash.STR_BYTES];
        boolean result = pwHashNative.cryptoPwHashStr(
                outputStr,
                PASSWORD_BYTES,
                PASSWORD_BYTES.length,
                PwHash.OPSLIMIT_MODERATE,
                PwHash.MEMLIMIT_MIN
        );
        assertTrue(result);

        assertTrue(pwHashNative.cryptoPwHashStrVerify(outputStr, PASSWORD_BYTES, PASSWORD_BYTES.length));
        assertFalse(pwHashNative.cryptoPwHashStrVerify(outputStr, PASSWORD_BYTES, PASSWORD_BYTES.length - 1));
    }

    @Test
    public void cryptoPwHashStrNativeChecks() {
        byte[] outputStr = new byte[PwHash.STR_BYTES];
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHashStr(new byte[PwHash.STR_BYTES - 1], PASSWORD_BYTES, PASSWORD_BYTES.length, PwHash.OPSLIMIT_MODERATE, PwHash.MEMLIMIT_MIN));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHashStr(outputStr, PASSWORD_BYTES, -1, PwHash.OPSLIMIT_MODERATE, PwHash.MEMLIMIT_MIN));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHashStr(outputStr, PASSWORD_BYTES, PASSWORD_BYTES.length + 1, PwHash.OPSLIMIT_MODERATE, PwHash.MEMLIMIT_MIN));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHashStr(outputStr, PASSWORD_BYTES, PASSWORD_BYTES.length, PwHash.OPSLIMIT_MIN - 1, new NativeLong(PwHash.MEMLIMIT_MIN.longValue() - 1)));
    }

    @Test
    public void cryptoPwHashStrVerifyNative() {
        assertTrue(pwHashNative.cryptoPwHashStrVerify(CORRECT_HASH_BYTES, PASSWORD_BYTES, PASSWORD_BYTES.length));
        assertFalse(pwHashNative.cryptoPwHashStrVerify(CORRECT_HASH_BYTES, PASSWORD_BYTES, PASSWORD_BYTES.length - 1));
    }

    @Test
    public void cryptoPwHashStrVerifyNativeChecks() {
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHashStrVerify(CORRECT_HASH.getBytes(StandardCharsets.UTF_8), PASSWORD_BYTES, PASSWORD_BYTES.length));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHashStrVerify(INVALID_TOO_LONG_HASH_BYTES, PASSWORD_BYTES, PASSWORD_BYTES.length));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHashStrVerify(CORRECT_HASH_BYTES, PASSWORD_BYTES, -1));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHashStrVerify(CORRECT_HASH_BYTES, PASSWORD_BYTES, PASSWORD_BYTES.length + 1));
    }

    @Test
    @SuppressWarnings("deprecation")
    public void cryptoPwHashStrLazy() throws SodiumException {
        String hash = pwHashLazy.cryptoPwHashStr(
                PASSWORD,
                PwHash.OPSLIMIT_MODERATE,
                PwHash.MEMLIMIT_MIN
        );

        assertTrue(pwHashLazy.cryptoPwHashStrVerify(hash, PASSWORD));
        assertFalse(pwHashLazy.cryptoPwHashStrVerify(hash, PASSWORD + "a"));
    }

    @Test
    @SuppressWarnings("deprecation")
    public void cryptoPwHashStrLazyChecks() {
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHashStr(PASSWORD, PwHash.OPSLIMIT_MIN - 1, PwHash.MEMLIMIT_MIN));
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHashStr(PASSWORD, PwHash.OPSLIMIT_MODERATE, new NativeLong(PwHash.MEMLIMIT_MIN.longValue() - 1)));
    }

    @Test
    @SuppressWarnings("deprecation")
    public void cryptoPwHashStrRemoveNulls() throws SodiumException {
        String hash = pwHashLazy.cryptoPwHashStrRemoveNulls(
                PASSWORD,
                PwHash.OPSLIMIT_MODERATE,
                PwHash.MEMLIMIT_MIN
        );

        assertTrue(pwHashLazy.cryptoPwHashStrVerify(hash, PASSWORD));
        assertFalse(pwHashLazy.cryptoPwHashStrVerify(hash, PASSWORD + "a"));
    }

    @Test
    @SuppressWarnings("deprecation")
    public void cryptoPwHashStrRemoveNullsChecks() {
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHashStrRemoveNulls(PASSWORD, PwHash.OPSLIMIT_MIN - 1, PwHash.MEMLIMIT_MIN));
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHashStrRemoveNulls(PASSWORD, PwHash.OPSLIMIT_MODERATE, new NativeLong(PwHash.MEMLIMIT_MIN.longValue() - 1)));
    }

    @Test
    @SuppressWarnings("deprecation")
    public void cryptoPwHashStrVerifyLazy() {
        assertTrue(pwHashLazy.cryptoPwHashStrVerify(CORRECT_HASH_HEX, PASSWORD));
        assertTrue(pwHashLazy.cryptoPwHashStrVerify(CORRECT_HASH_HEX_WITH_ZERO, PASSWORD));
        assertTrue(pwHashLazy.cryptoPwHashStrVerify(CORRECT_HASH_HEX_WITH_ZEROES, PASSWORD));
        assertFalse(pwHashLazy.cryptoPwHashStrVerify(CORRECT_HASH_HEX, PASSWORD + "a"));
        assertFalse(pwHashLazy.cryptoPwHashStrVerify(CORRECT_HASH_HEX_WITH_ZERO, PASSWORD + "a"));
        assertFalse(pwHashLazy.cryptoPwHashStrVerify(CORRECT_HASH_HEX_WITH_ZEROES, PASSWORD + "a"));
    }

    @Test
    @SuppressWarnings("deprecation")
    public void cryptoPwHashStrVerifyLazyChecks() {
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHashStrVerify(INVALID_TOO_LONG_HASH_HEX, PASSWORD));
    }

    @Test
    public void cryptoPwHashString() throws SodiumException {
        String hash = pwHashLazy.cryptoPwHashString(
                PASSWORD,
                PwHash.OPSLIMIT_MODERATE,
                PwHash.MEMLIMIT_MIN
        );

        assertTrue(pwHashLazy.cryptoPwHashStringVerify(hash, PASSWORD));
        assertFalse(pwHashLazy.cryptoPwHashStringVerify(hash, PASSWORD + "a"));
    }

    @Test
    public void cryptoPwHashStringChecks() {
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHashString(PASSWORD, PwHash.OPSLIMIT_MIN - 1, PwHash.MEMLIMIT_MIN));
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHashString(PASSWORD, PwHash.OPSLIMIT_MODERATE, new NativeLong(PwHash.MEMLIMIT_MIN.longValue() - 1)));
    }

    @Test
    public void cryptoPwVerifyString() {
        assertTrue(pwHashLazy.cryptoPwHashStringVerify(CORRECT_HASH, PASSWORD));
        assertFalse(pwHashLazy.cryptoPwHashStringVerify(CORRECT_HASH, PASSWORD + "a"));
    }

    @Test
    public void cryptoPwVerifyStringChecks() {
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHashStringVerify(INVALID_TOO_LONG_HASH, PASSWORD));
    }

    @Test
    public void cryptoPwHashStrNeedsRehashNative() {
        final NativeLong usedMemLimit = new NativeLong(262144);
        assertEquals(PwHash.NeedsRehashResult.NO_REHASH_NEEDED, pwHashNative.cryptoPwHashStrNeedsRehash(CORRECT_HASH_BYTES, PwHash.OPSLIMIT_INTERACTIVE, usedMemLimit));
        assertEquals(PwHash.NeedsRehashResult.NEEDS_REHASH, pwHashNative.cryptoPwHashStrNeedsRehash(CORRECT_HASH_BYTES, PwHash.OPSLIMIT_MAX, usedMemLimit));
        assertEquals(PwHash.NeedsRehashResult.NEEDS_REHASH, pwHashNative.cryptoPwHashStrNeedsRehash(CORRECT_HASH_BYTES, PwHash.OPSLIMIT_INTERACTIVE, PwHash.MEMLIMIT_MAX));
        assertEquals(PwHash.NeedsRehashResult.INVALID_HASH, pwHashNative.cryptoPwHashStrNeedsRehash("Not a useful hash string\u0000".getBytes(StandardCharsets.UTF_8), PwHash.OPSLIMIT_INTERACTIVE, PwHash.MEMLIMIT_MAX));
    }

    @Test
    public void cryptoPwHashStrNeedsRehashNativeChecks() {
        final NativeLong usedMemLimit = new NativeLong(262144);
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHashStrNeedsRehash(CORRECT_HASH.getBytes(StandardCharsets.UTF_8), PwHash.OPSLIMIT_INTERACTIVE, usedMemLimit));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHashStrNeedsRehash(INVALID_TOO_LONG_HASH_BYTES, PwHash.OPSLIMIT_INTERACTIVE, usedMemLimit));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHashStrNeedsRehash(CORRECT_HASH_BYTES, PwHash.OPSLIMIT_MIN - 1, usedMemLimit));
        assertThrows(IllegalArgumentException.class, () -> pwHashNative.cryptoPwHashStrNeedsRehash(CORRECT_HASH_BYTES, PwHash.OPSLIMIT_INTERACTIVE, new NativeLong(PwHash.MEMLIMIT_MIN.longValue() - 1)));
    }

    @Test
    public void cryptoPwHashStrNeedsRehashLazy() {
        final NativeLong usedMemLimit = new NativeLong(262144);
        assertEquals(PwHash.NeedsRehashResult.NO_REHASH_NEEDED, pwHashLazy.cryptoPwHashStringNeedsRehash(CORRECT_HASH, PwHash.OPSLIMIT_INTERACTIVE, usedMemLimit));
        assertEquals(PwHash.NeedsRehashResult.NEEDS_REHASH, pwHashLazy.cryptoPwHashStringNeedsRehash(CORRECT_HASH, PwHash.OPSLIMIT_MAX, usedMemLimit));
        assertEquals(PwHash.NeedsRehashResult.NEEDS_REHASH, pwHashLazy.cryptoPwHashStringNeedsRehash(CORRECT_HASH, PwHash.OPSLIMIT_INTERACTIVE, PwHash.MEMLIMIT_MAX));
        assertEquals(PwHash.NeedsRehashResult.INVALID_HASH, pwHashLazy.cryptoPwHashStringNeedsRehash("Not a useful hash string", PwHash.OPSLIMIT_INTERACTIVE, usedMemLimit));
    }

    @Test
    public void cryptoPwHashStrNeedsRehashLazyChecks() {
        final NativeLong usedMemLimit = new NativeLong(262144);
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHashStringNeedsRehash(INVALID_TOO_LONG_HASH, PwHash.OPSLIMIT_INTERACTIVE, usedMemLimit));
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHashStringNeedsRehash(CORRECT_HASH, PwHash.OPSLIMIT_MIN - 1, usedMemLimit));
        assertThrows(IllegalArgumentException.class, () -> pwHashLazy.cryptoPwHashStringNeedsRehash(CORRECT_HASH, PwHash.OPSLIMIT_INTERACTIVE, new NativeLong(PwHash.MEMLIMIT_MIN.longValue() - 1)));
    }

}
