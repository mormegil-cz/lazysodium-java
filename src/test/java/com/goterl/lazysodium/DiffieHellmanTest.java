/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.Box;
import com.goterl.lazysodium.interfaces.DiffieHellman;
import com.goterl.lazysodium.interfaces.SecretBox;
import com.goterl.lazysodium.utils.Key;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DiffieHellmanTest extends BaseTest {

    private static final String CLIENT_SECRET_KEY = "CLIENT_TOP_SECRET_KEY_1234567890";
    private static final byte[] CLIENT_SECRET_KEY_BYTES = CLIENT_SECRET_KEY.getBytes(StandardCharsets.UTF_8);
    private static final String SERVER_SECRET_KEY = "SERVER_TOP_SECRET_KEY_1234567890";
    private static final byte[] SERVER_SECRET_KEY_BYTES = SERVER_SECRET_KEY.getBytes(StandardCharsets.UTF_8);

    private DiffieHellman.Native dhNative;
    private DiffieHellman.Lazy dhLazy;

    @BeforeAll
    public void before() {
        dhNative = lazySodium;
        dhLazy = lazySodium;
    }

    @Test
    public void create() throws SodiumException {
        SecretBox.Lazy box = lazySodium;

        Key secretKeyC = Key.fromPlainString(CLIENT_SECRET_KEY);
        Key publicKeyC = dhLazy.cryptoScalarMultBase(secretKeyC);

        Key secretKeyS = Key.fromPlainString(SERVER_SECRET_KEY);
        Key publicKeyS = dhLazy.cryptoScalarMultBase(secretKeyS);

        // -----
        // ON THE CLIENT
        // -----

        // Compute a shared key for sending from client
        // to server.
        Key sharedKey = dhLazy.cryptoScalarMult(secretKeyC, publicKeyS);

        String message = "Hello";
        byte[] nonce = new byte[Box.NONCEBYTES];
        String encrypted = box.cryptoSecretBoxEasy(message, nonce, sharedKey);

        // Send 'encrypted' to server...


        // -----
        // ON THE SERVER
        // -----

        // Compute the shared key for receiving server messages from client
        Key sharedKeyServer = dhLazy.cryptoScalarMult(secretKeyS, publicKeyC);
        String decrypted = box.cryptoSecretBoxOpenEasy(encrypted, nonce, sharedKeyServer);

        // 'decrypted' == Hello

        assertEquals(message, decrypted);
    }

    @Test
    public void cryptoScalarMultBaseChecks() {
        byte[] publicKeyBytes = new byte[DiffieHellman.SCALARMULT_BYTES];
        assertThrows(IllegalArgumentException.class, () -> dhNative.cryptoScalarMultBase(new byte[DiffieHellman.SCALARMULT_BYTES - 1], CLIENT_SECRET_KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> dhNative.cryptoScalarMultBase(new byte[DiffieHellman.SCALARMULT_BYTES + 1], CLIENT_SECRET_KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> dhNative.cryptoScalarMultBase(publicKeyBytes, new byte[DiffieHellman.SCALARMULT_SCALARBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> dhNative.cryptoScalarMultBase(publicKeyBytes, new byte[DiffieHellman.SCALARMULT_SCALARBYTES + 1]));
    }

    @Test
    public void cryptoScalarMultChecks() {
        byte[] sharedKeyBytes = new byte[DiffieHellman.SCALARMULT_BYTES];
        byte[] publicKeyBytes = new byte[DiffieHellman.SCALARMULT_BYTES];
        assertTrue(dhNative.cryptoScalarMultBase(publicKeyBytes, CLIENT_SECRET_KEY_BYTES));

        assertThrows(IllegalArgumentException.class, () -> dhNative.cryptoScalarMult(new byte[DiffieHellman.SCALARMULT_BYTES - 1], publicKeyBytes, CLIENT_SECRET_KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> dhNative.cryptoScalarMult(new byte[DiffieHellman.SCALARMULT_BYTES + 1], publicKeyBytes, CLIENT_SECRET_KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> dhNative.cryptoScalarMult(sharedKeyBytes, new byte[DiffieHellman.SCALARMULT_BYTES - 1], CLIENT_SECRET_KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> dhNative.cryptoScalarMult(sharedKeyBytes, new byte[DiffieHellman.SCALARMULT_BYTES + 1], CLIENT_SECRET_KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> dhNative.cryptoScalarMult(sharedKeyBytes, publicKeyBytes, new byte[DiffieHellman.SCALARMULT_SCALARBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> dhNative.cryptoScalarMult(sharedKeyBytes, publicKeyBytes, new byte[DiffieHellman.SCALARMULT_SCALARBYTES + 1]));
    }
}
