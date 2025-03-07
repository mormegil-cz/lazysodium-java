/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.Hash;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class HashTest extends BaseTest {
    private static final String M1 = "With great power ";
    private static final String M2 = "comes great responsibility";
    private static final String MESSAGE = M1 + M2;
    private static final byte[] MESSAGE_BYTES = MESSAGE.getBytes(StandardCharsets.UTF_8);

    private Hash.Lazy hashLazy;
    private Hash.Native hashNative;

    @BeforeAll
    public void before() {
        hashLazy = lazySodium;
        hashNative = lazySodium;
    }

    @Test
    public void sha256Compare() throws SodiumException {
        String hashed1 = hashLazy.cryptoHashSha256(MESSAGE);
        String hashed2 = hashLazy.cryptoHashSha256(MESSAGE);
        String hashed3 = hashLazy.cryptoHashSha256(MESSAGE + ".");
        assertNotSame(hashed1, hashed2);
        assertEquals(hashed1, hashed2);
        assertNotEquals(hashed1, hashed3);
    }

    @Test
    public void sha512Compare() throws SodiumException {
        String hash1 = hashLazy.cryptoHashSha512(MESSAGE);
        String hash2 = hashLazy.cryptoHashSha512(MESSAGE);
        String hash3 = hashLazy.cryptoHashSha512(MESSAGE + ".");
        assertNotSame(hash1, hash2);
        assertEquals(hash1, hash2);
        assertNotEquals(hash1, hash3);
    }

    @Test
    public void sha512IsLonger() throws SodiumException {
        String hash1 = hashLazy.cryptoHashSha256(MESSAGE);
        String hash2 = hashLazy.cryptoHashSha512(MESSAGE);
        assertTrue(hash1.length() < hash2.length());
    }

    @Test
    public void cryptoHashSha256Lazy() throws SodiumException {
        String emptyStrHash = hashLazy.cryptoHashSha256("");
        String messageHash = hashLazy.cryptoHashSha256(MESSAGE);

        assertEquals("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", emptyStrHash);
        assertEquals("C3AD802153EC95A762B7E86CCD4D53C34DA431AE47D96937D05B1369DA551A5B", messageHash);
    }

    @Test
    public void cryptoHashSha256Native() {
        byte[] emptyStrHash = new byte[Hash.SHA256_BYTES];
        boolean success1 = hashNative.cryptoHashSha256(emptyStrHash, new byte[0], 0);
        byte[] messageHash = new byte[Hash.SHA256_BYTES];
        boolean success2 = hashNative.cryptoHashSha256(messageHash, MESSAGE_BYTES, MESSAGE_BYTES.length);

        assertTrue(success1);
        assertTrue(success2);
        assertArrayEquals(lazySodium.toBinary("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"), emptyStrHash);
        assertArrayEquals(lazySodium.toBinary("C3AD802153EC95A762B7E86CCD4D53C34DA431AE47D96937D05B1369DA551A5B"), messageHash);
    }

    @Test
    public void cryptoHashSha256NativeChecks() {
        assertThrows(IllegalArgumentException.class, () -> hashNative.cryptoHashSha256(new byte[Hash.SHA256_BYTES - 1], MESSAGE_BYTES, MESSAGE_BYTES.length));
        assertThrows(IllegalArgumentException.class, () -> hashNative.cryptoHashSha256(new byte[Hash.SHA256_BYTES + 1], MESSAGE_BYTES, MESSAGE_BYTES.length));
        assertThrows(IllegalArgumentException.class, () -> hashNative.cryptoHashSha256(new byte[Hash.SHA256_BYTES], MESSAGE_BYTES, -1));
        assertThrows(IllegalArgumentException.class, () -> hashNative.cryptoHashSha256(new byte[Hash.SHA256_BYTES], MESSAGE_BYTES, MESSAGE_BYTES.length + 1));
    }

    @Test
    public void multipartSha256Lazy() throws SodiumException {
        Hash.State256 state = new Hash.State256.ByReference();
        hashLazy.cryptoHashSha256Init(state);

        hashLazy.cryptoHashSha256Update(state, M1);
        hashLazy.cryptoHashSha256Update(state, M2);
        hashLazy.cryptoHashSha256Update(state, "more text to be hashed");
        hashLazy.cryptoHashSha256Update(state, "...");

        String hash1 = hashLazy.cryptoHashSha256Final(state);
        assertNotNull(hash1);

        hashLazy.cryptoHashSha256Init(state);

        hashLazy.cryptoHashSha256Update(state, M1 + M2);
        hashLazy.cryptoHashSha256Update(state, "more text to be hashed.");
        hashLazy.cryptoHashSha256Update(state, "..");

        String hash2 = hashLazy.cryptoHashSha256Final(state);
        assertEquals(hash1, hash2);
    }

    @Test
    public void multipartSha256Native() {
        Hash.State256 state = new Hash.State256.ByReference();
        assertTrue(hashNative.cryptoHashSha256Init(state));
        assertTrue(hashNative.cryptoHashSha256Update(state, MESSAGE_BYTES, MESSAGE_BYTES.length));
        assertTrue(hashNative.cryptoHashSha256Update(state, MESSAGE_BYTES, 10));
        byte[] hash = new byte[Hash.SHA256_BYTES];
        assertTrue(hashNative.cryptoHashSha256Final(state, hash));
        assertArrayEquals(lazySodium.toBinary("96B84DCEE60718D64E59A1AE3E92AC7D22EE524FE1E73DD46786D15C750D4E7B"), hash);
    }

    @Test
    public void multipartSha256NativeChecks() {
        Hash.State256 state = new Hash.State256.ByReference();
        hashNative.cryptoHashSha256Init(state);
        assertThrows(IllegalArgumentException.class, () -> hashNative.cryptoHashSha256Final(state, new byte[Hash.SHA256_BYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> hashNative.cryptoHashSha256Final(state, new byte[Hash.SHA256_BYTES + 1]));
    }

    @Test
    public void cryptoHashSha512Lazy() throws SodiumException {
        String emptyStrHash = hashLazy.cryptoHashSha512("");
        String messageHash = hashLazy.cryptoHashSha512(MESSAGE);

        assertEquals("CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E", emptyStrHash);
        assertEquals("C8DC1DB5142A701D1838311F8EE338AF88E5FC78869F96544C75E09A3A91737BF533C8601869E1FB0B76808F9DBBC4736FF249582B1F1BF5F2EF480D80ABA2EC", messageHash);
    }

    @Test
    public void cryptoHashSha512Native() {
        byte[] emptyStrHash = new byte[Hash.SHA512_BYTES];
        boolean success1 = hashNative.cryptoHashSha512(emptyStrHash, new byte[0], 0);
        byte[] messageHash = new byte[Hash.SHA512_BYTES];
        boolean success2 = hashNative.cryptoHashSha512(messageHash, MESSAGE_BYTES, MESSAGE_BYTES.length);

        assertTrue(success1);
        assertTrue(success2);
        assertArrayEquals(lazySodium.toBinary("CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"), emptyStrHash);
        assertArrayEquals(lazySodium.toBinary("C8DC1DB5142A701D1838311F8EE338AF88E5FC78869F96544C75E09A3A91737BF533C8601869E1FB0B76808F9DBBC4736FF249582B1F1BF5F2EF480D80ABA2EC"), messageHash);
    }

    @Test
    public void cryptoHashSha512NativeChecks() {
        assertThrows(IllegalArgumentException.class, () -> hashNative.cryptoHashSha512(new byte[Hash.SHA512_BYTES - 1], MESSAGE_BYTES, MESSAGE_BYTES.length));
        assertThrows(IllegalArgumentException.class, () -> hashNative.cryptoHashSha512(new byte[Hash.SHA512_BYTES + 1], MESSAGE_BYTES, MESSAGE_BYTES.length));
        assertThrows(IllegalArgumentException.class, () -> hashNative.cryptoHashSha512(new byte[Hash.SHA512_BYTES], MESSAGE_BYTES, -1));
        assertThrows(IllegalArgumentException.class, () -> hashNative.cryptoHashSha512(new byte[Hash.SHA512_BYTES], MESSAGE_BYTES, MESSAGE_BYTES.length + 1));
    }

    @Test
    public void multipartSha512Lazy() throws SodiumException {
        Hash.State512 state = new Hash.State512.ByReference();
        hashLazy.cryptoHashSha512Init(state);

        hashLazy.cryptoHashSha512Update(state, M1);
        hashLazy.cryptoHashSha512Update(state, M2);
        hashLazy.cryptoHashSha512Update(state, "more text to be hashed");
        hashLazy.cryptoHashSha512Update(state, "...");

        String hash1 = hashLazy.cryptoHashSha512Final(state);
        assertNotNull(hash1);

        hashLazy.cryptoHashSha512Init(state);

        hashLazy.cryptoHashSha512Update(state, M1 + M2);
        hashLazy.cryptoHashSha512Update(state, "more text to be hashed.");
        hashLazy.cryptoHashSha512Update(state, "..");

        String hash2 = hashLazy.cryptoHashSha512Final(state);
        assertEquals(hash1, hash2);
    }

    @Test
    public void multipartSha512Native() {
        Hash.State512 state = new Hash.State512.ByReference();
        assertTrue(hashNative.cryptoHashSha512Init(state));
        assertTrue(hashNative.cryptoHashSha512Update(state, MESSAGE_BYTES, MESSAGE_BYTES.length));
        assertTrue(hashNative.cryptoHashSha512Update(state, MESSAGE_BYTES, 10));
        byte[] hash = new byte[Hash.SHA512_BYTES];
        assertTrue(hashNative.cryptoHashSha512Final(state, hash));
        assertArrayEquals(lazySodium.toBinary("1A3864B1392A0223660C9369C833615BA19477C2CE464F11C2E77E925EB36547AFAE01F85831BB5DDC87BAC9B0D9E2C1EF5A1F3016370AC8455FB8343C5B6E2A"), hash);
    }

    @Test
    public void multipartSha512NativeChecks() {
        Hash.State512 state = new Hash.State512.ByReference();
        hashNative.cryptoHashSha512Init(state);
        assertThrows(IllegalArgumentException.class, () -> hashNative.cryptoHashSha512Final(state, new byte[Hash.SHA512_BYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> hashNative.cryptoHashSha512Final(state, new byte[Hash.SHA512_BYTES + 1]));
    }
}
