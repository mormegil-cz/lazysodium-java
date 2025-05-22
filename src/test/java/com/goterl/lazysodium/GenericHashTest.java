/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.GenericHash;
import com.goterl.lazysodium.utils.Key;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class GenericHashTest extends BaseTest {

    private GenericHash.Lazy genHashLazy;
    private GenericHash.Native genHashNative;

    @BeforeAll
    public void before() {
        genHashLazy = lazySodium;
        genHashNative = lazySodium;
    }

    @Test
    public void genKey() {
        Key key = genHashLazy.cryptoGenericHashKeygen();
        assertNotNull(key);
    }

    @Test
    public void hash() throws SodiumException {
        String message = "https://terl.co";
        Key key = genHashLazy.cryptoGenericHashKeygen();
        String hash = genHashLazy.cryptoGenericHash(message, key);
        assertNotNull(hash);
    }

    @Test
    public void hashNoKey() throws SodiumException {
        String message = "https://terl.co";
        String hash = genHashLazy.cryptoGenericHash(message);
        assertNotNull(hash);
    }

    @Test
    public void hashEmpty() {
        byte[] out = new byte[GenericHash.BYTES_MAX];
        boolean ok = genHashNative.cryptoGenericHash(out, out.length, new byte[0], 0);
        assertTrue(ok);
        // See https://en.wikipedia.org/wiki/BLAKE_(hash_function)?oldid=1291503427#Example_digests_2
        assertEquals("786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE", lazySodium.toHexStr(out));
    }

    @Test
    public void hashKeyedEmptyTestVector() {
        byte[] out = new byte[GenericHash.BYTES_MAX];
        byte[] key = lazySodium.sodiumHex2Bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        boolean ok = genHashNative.cryptoGenericHash(out, out.length, new byte[0], 0, key, key.length);
        assertTrue(ok);
        // See https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2b-kat.txt
        assertEquals("10EBB67700B1868EFB4417987ACF4690AE9D972FB7A590C2F02871799AAA4786B5E996E8F0F4EB981FC214B005F42D2FF4233499391653DF7AEFCBC13FC51568", lazySodium.toHexStr(out));
    }

    @Test
    public void hashKeyedNonEmptyTestVector() {
        byte[] out = new byte[GenericHash.BYTES_MAX];
        byte[] in = lazySodium.sodiumHex2Bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425");
        byte[] key = lazySodium.sodiumHex2Bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        boolean ok = genHashNative.cryptoGenericHash(out, out.length, in, in.length, key, key.length);
        assertTrue(ok);
        // See https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2b-kat.txt
        assertEquals("D1B897B0E075BA68AB572ADF9D9C436663E43EB3D8E62D92FC49C9BE214E6F27873FE215A65170E6BEA902408A25B49506F47BABD07CECF7113EC10C5DD31252", lazySodium.toHexStr(out));
    }

    @Test
    public void hashKeyedNonEmptyTestVectorMultipart() {
        final int TEST_END = 0x9F;
        byte[] out = new byte[GenericHash.BYTES_MAX];
        byte[] inBuf = new byte[17];
        byte[] key = lazySodium.sodiumHex2Bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        try (GenericHash.State state = new GenericHash.State()) {
            genHashNative.cryptoGenericHashInit(state, key, key.length, out.length);
            for (int i = 0; i <= TEST_END; i += inBuf.length) {
                for (int j = 0; j < inBuf.length && (i + j) <= TEST_END; ++j) {
                    inBuf[j] = (byte) (i + j);
                }
                boolean ok = genHashNative.cryptoGenericHashUpdate(state, inBuf, Math.min(inBuf.length, TEST_END - i + 1));
                assertTrue(ok);
            }
            boolean res = genHashNative.cryptoGenericHashFinal(state, out, out.length);
            assertTrue(res);
        }
        // See https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2b-kat.txt
        assertEquals("E58B3836B7D8FEDBB50CA5725C6571E74C0785E97821DAB8B6298C10E4C079D4A6CDF22F0FEDB55032925C16748115F01A105E77E00CEE3D07924DC0D8F90659", lazySodium.toHexStr(out));
    }

    @Test
    public void hashMultiPartNoKey() throws SodiumException {
        String hash = hashMultiPart(
                0,
                GenericHash.BYTES_MAX,
                "The quick brown ",
                "fox jumps ",
                "over the ",
                "lazy dog"
        );

        // See https://en.wikipedia.org/wiki/BLAKE_(hash_function)?oldid=1291503427#Example_digests_2
        assertEquals("A8ADD4BDDDFD93E4877D2746E62817B116364A1FA7BC148D95090BC7333B3673F82401CF7AA2E4CB1ECD90296E3F14CB5413F8ED77BE73045B13914CDCD6A918", hash);
    }


    @Test
    public void hashMultiPartSingleByte() throws SodiumException {
        String message = "The sun";
        String message2 = "is shining";

        String hash = hashMultiPart(
                1,
                GenericHash.BYTES,
                message,
                message2
        );


        assertNotNull(hash);
    }

    @Test
    public void hashMultiPartMinimum() throws SodiumException {
        String message = "The sun";
        String message2 = "is shining";

        String hash = hashMultiPart(
                GenericHash.KEYBYTES_MIN,
                GenericHash.BYTES,
                message,
                message2
        );


        assertNotNull(hash);
    }

    @Test
    public void hashMultiPartRecommended() throws SodiumException {
        String message = "The sun";
        String message2 = "is shining";

        String hash = hashMultiPart(
                GenericHash.KEYBYTES,
                GenericHash.BYTES,
                message,
                message2
        );


        assertNotNull(hash);
    }

    @Test
    public void hashMultiPartMax() throws SodiumException {
        String message = "Do not go gentle into that good night";
        String message2 = "Old age should burn and rave at close of day";
        String message3 = "Rage, rage against the dying of the light";

        String hash = hashMultiPart(
                GenericHash.KEYBYTES_MAX,
                GenericHash.BYTES_MAX,
                message,
                message2,
                message3
        );

        assertNotNull(hash);
    }


    private String hashMultiPart(int keySize, int hashSize, String... messages) throws SodiumException {

        Key key = keySize == 0 ? null : genHashLazy.cryptoGenericHashKeygen(keySize);
        try (GenericHash.State state = new GenericHash.State()) {
            assertTrue(genHashLazy.cryptoGenericHashInit(state, key, hashSize));

            for (String msg : messages) {
                assertTrue(genHashLazy.cryptoGenericHashUpdate(state, msg));
            }

            return genHashLazy.cryptoGenericHashFinal(state, hashSize);
        }
    }


    @Test
    public void cryptoGenericHashChecks() {
        byte[] out = new byte[GenericHash.BYTES_MAX];
        byte[] in = new byte[10];
        byte[] key = new byte[GenericHash.KEYBYTES_MAX];
        assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHash(out, -1, in, in.length, key, key.length));
        assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHash(out, 0, in, in.length, key, key.length));
        assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHash(out, out.length + 1, in, in.length, key, key.length));
        assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHash(new byte[GenericHash.BYTES_MAX + 1], GenericHash.BYTES_MAX + 1, in, in.length, key, key.length));
        assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHash(out, out.length, in, -1, key, key.length));
        assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHash(out, out.length, in, in.length + 1, key, key.length));
        assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHash(out, out.length, in, in.length, key, -1));
        assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHash(out, out.length, in, in.length, key, 0));
        assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHash(out, out.length, in, in.length, key, key.length + 1));
        assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHash(out, out.length, in, in.length, new byte[GenericHash.KEYBYTES_MAX + 1], GenericHash.KEYBYTES_MAX + 1));
    }

    @Test
    public void cryptoGenericHashInitChecks() {
        try (GenericHash.State state = new GenericHash.State()) {
            byte[] key = new byte[GenericHash.KEYBYTES_MAX];
            assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHashInit(state, key, -1, GenericHash.BYTES));
            assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHashInit(state, key, 0, GenericHash.BYTES));
            assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHashInit(state, key, key.length + 1, GenericHash.BYTES));
            assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHashInit(state, new byte[GenericHash.KEYBYTES_MAX + 1], GenericHash.KEYBYTES_MAX + 1, GenericHash.BYTES));
            assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHashInit(state, key, key.length, -1));
            assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHashInit(state, key, key.length, 0));
            assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHashInit(state, key, key.length, GenericHash.BYTES_MAX + 1));
        }
    }

    @Test
    public void cryptoGenericHashUpdateChecks() {
        try (GenericHash.State state = new GenericHash.State()) {
            byte[] in = new byte[10];
            assertTrue(genHashNative.cryptoGenericHashInit(state, GenericHash.BYTES_MAX));
            assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHashUpdate(state, in, -1));
            assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHashUpdate(state, in, in.length + 1));
        }
    }

    @Test
    public void cryptoGenericHashFinalChecks() {
        try (GenericHash.State state = new GenericHash.State()) {
            byte[] out = new byte[GenericHash.BYTES_MAX + 1];
            assertTrue(genHashNative.cryptoGenericHashInit(state, GenericHash.BYTES_MAX));
            assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHashFinal(state, out, -1));
            assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHashFinal(state, out, out.length + 1));
            assertThrows(IllegalArgumentException.class, () -> genHashNative.cryptoGenericHashFinal(state, out, out.length));
        }
    }

}
