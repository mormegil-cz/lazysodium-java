/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.SecretStream;
import com.goterl.lazysodium.utils.Key;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SecretStreamTest extends BaseTest {
    private SecretStream.Lazy secretStreamLazy;
    private SecretStream.Native secretStreamNative;

    private static final String message1 = "Arbitrary data to encrypt";
    private static final String message2 = "split into";
    private static final String message3 = "three messages";


    @BeforeAll
    public void before() {
        secretStreamLazy = lazySodium;
        secretStreamNative = lazySodium;
    }

    @Test
    public void test1() throws SodiumException {
        Key key = secretStreamLazy.cryptoSecretStreamKeygen();

        byte[] header = new byte[SecretStream.HEADERBYTES];

        // Start the encryption
        SecretStream.State state = secretStreamLazy.cryptoSecretStreamInitPush(header, key);

        String c1 = secretStreamLazy.cryptoSecretStreamPush(state, message1, SecretStream.TAG_MESSAGE);
        String c2 = secretStreamLazy.cryptoSecretStreamPush(state, message2, SecretStream.TAG_MESSAGE);
        String c3 = secretStreamLazy.cryptoSecretStreamPush(state, message3, SecretStream.TAG_FINAL);

        // Start the decryption
        byte[] tag = new byte[1];

        SecretStream.State state2 = secretStreamLazy.cryptoSecretStreamInitPull(header, key);

        String decryptedMessage = secretStreamLazy.cryptoSecretStreamPull(state2, c1, tag);
        String decryptedMessage2 = secretStreamLazy.cryptoSecretStreamPull(state2, c2, tag);
        String decryptedMessage3 = secretStreamLazy.cryptoSecretStreamPull(state2, c3, tag);

        assertEquals(SecretStream.XCHACHA20POLY1305_TAG_FINAL, tag[0]);

        assertEquals(message1, decryptedMessage);
        assertEquals(message2, decryptedMessage2);
        assertEquals(message3, decryptedMessage3);
    }

    @Test
    public void testInvalidKeySize() {
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamKeygen(new byte[SecretStream.KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamKeygen(new byte[SecretStream.KEYBYTES + 1]));
    }

    @Test
    public void testStreamKeyGenChecks() {
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamKeygen(new byte[SecretStream.KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamKeygen(new byte[SecretStream.KEYBYTES + 1]));
    }

    @Test
    public void testInitPushChecks() {
        Key goodKey = secretStreamLazy.cryptoSecretStreamKeygen();

        assertThrows(IllegalArgumentException.class, () -> secretStreamLazy.cryptoSecretStreamInitPush(new byte[SecretStream.HEADERBYTES - 1], goodKey));
        assertThrows(IllegalArgumentException.class, () -> secretStreamLazy.cryptoSecretStreamInitPush(new byte[SecretStream.HEADERBYTES + 1], goodKey));
        assertThrows(IllegalArgumentException.class, () -> secretStreamLazy.cryptoSecretStreamInitPush(new byte[SecretStream.HEADERBYTES], Key.fromBytes(new byte[SecretStream.KEYBYTES - 1])));
        assertThrows(IllegalArgumentException.class, () -> secretStreamLazy.cryptoSecretStreamInitPush(new byte[SecretStream.HEADERBYTES], Key.fromBytes(new byte[SecretStream.KEYBYTES + 1])));

        SecretStream.State state = new SecretStream.State();
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamInitPush(state, new byte[SecretStream.HEADERBYTES - 1], goodKey.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamInitPush(state, new byte[SecretStream.HEADERBYTES + 1], goodKey.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamInitPush(state, new byte[SecretStream.HEADERBYTES], new byte[SecretStream.KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamInitPush(state, new byte[SecretStream.HEADERBYTES], new byte[SecretStream.KEYBYTES + 1]));
    }

    @Test
    public void testPushChecks() throws SodiumException {
        byte[] header = new byte[SecretStream.HEADERBYTES];
        Key key = secretStreamLazy.cryptoSecretStreamKeygen();

        SecretStream.State state = secretStreamLazy.cryptoSecretStreamInitPush(header, key);
        byte[] message = message1.getBytes(StandardCharsets.UTF_8);
        byte[] cipherBuf = new byte[message.length + SecretStream.ABYTES];
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPush(state, cipherBuf, null, message, -1, (byte) 0));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPush(state, cipherBuf, null, message, message.length + 1, (byte) 0));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPush(state, new byte[cipherBuf.length - 1], null, message, message.length, (byte) 0));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPush(state, cipherBuf, new long[0], message, message.length, (byte) 0));

        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPush(state, cipherBuf, message, -1, (byte) 0));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPush(state, cipherBuf, message, message.length + 1, (byte) 0));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPush(state, new byte[cipherBuf.length - 1], message, message.length, (byte) 0));

        byte[] additionalData = new byte[100];
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPush(state, cipherBuf, null, message, -1, additionalData, additionalData.length, (byte) 0));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPush(state, cipherBuf, null, message, message.length + 1, additionalData, additionalData.length, (byte) 0));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPush(state, new byte[cipherBuf.length - 1], null, message, message.length, additionalData, additionalData.length, (byte) 0));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPush(state, cipherBuf, new long[0], message, message.length, additionalData, additionalData.length, (byte) 0));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPush(state, cipherBuf, null, message, message.length, additionalData, -1, (byte) 0));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPush(state, cipherBuf, null, message, message.length, additionalData, additionalData.length + 1, (byte) 0));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPush(state, cipherBuf, null, message, message.length, null, additionalData.length, (byte) 0));
    }

    @Test
    public void testInitPullChecks() {
        Key goodKey = secretStreamLazy.cryptoSecretStreamKeygen();

        assertThrows(IllegalArgumentException.class, () -> secretStreamLazy.cryptoSecretStreamInitPull(new byte[SecretStream.HEADERBYTES - 1], goodKey));
        assertThrows(IllegalArgumentException.class, () -> secretStreamLazy.cryptoSecretStreamInitPull(new byte[SecretStream.HEADERBYTES + 1], goodKey));
        assertThrows(IllegalArgumentException.class, () -> secretStreamLazy.cryptoSecretStreamInitPull(new byte[SecretStream.HEADERBYTES], Key.fromBytes(new byte[SecretStream.KEYBYTES - 1])));
        assertThrows(IllegalArgumentException.class, () -> secretStreamLazy.cryptoSecretStreamInitPull(new byte[SecretStream.HEADERBYTES], Key.fromBytes(new byte[SecretStream.KEYBYTES + 1])));

        SecretStream.State state = new SecretStream.State();
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamInitPull(state, new byte[SecretStream.HEADERBYTES - 1], goodKey.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamInitPull(state, new byte[SecretStream.HEADERBYTES + 1], goodKey.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamInitPull(state, new byte[SecretStream.HEADERBYTES], new byte[SecretStream.KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamInitPull(state, new byte[SecretStream.HEADERBYTES], new byte[SecretStream.KEYBYTES + 1]));
    }

    @Test
    public void testPullChecks() throws SodiumException {
        byte[] header = new byte[SecretStream.HEADERBYTES];
        Key key = secretStreamLazy.cryptoSecretStreamKeygen();

        SecretStream.State state = secretStreamLazy.cryptoSecretStreamInitPull(header, key);
        byte[] message = message1.getBytes(StandardCharsets.UTF_8);
        byte[] cipher = new byte[message.length + SecretStream.ABYTES];
        byte[] messageBuf = new byte[message.length];
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPull(state, messageBuf, null, cipher, -1));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPull(state, messageBuf, null, cipher, cipher.length + 1));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPull(state, new byte[messageBuf.length - 1], null, cipher, cipher.length));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPull(state, messageBuf, new byte[0], cipher, cipher.length));

        byte[] additionalData = new byte[100];
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPull(state, messageBuf, null, null, cipher, -1, additionalData, additionalData.length));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPull(state, messageBuf, null, null, cipher, cipher.length + 1, additionalData, additionalData.length));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPull(state, new byte[messageBuf.length - 1], null, null, cipher, cipher.length, additionalData, additionalData.length));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPull(state, messageBuf, null, new byte[0], cipher, cipher.length, additionalData, additionalData.length));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPull(state, messageBuf, null, null, cipher, cipher.length, additionalData, -1));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPull(state, messageBuf, null, null, cipher, cipher.length, additionalData, additionalData.length + 1));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPull(state, messageBuf, null, null, cipher, cipher.length, null, additionalData.length));
        assertThrows(IllegalArgumentException.class, () -> secretStreamNative.cryptoSecretStreamPull(state, messageBuf, new long[0], null, cipher, cipher.length, additionalData, additionalData.length));

        assertThrows(IllegalArgumentException.class, () -> secretStreamLazy.cryptoSecretStreamPull(state, "", null));
        String cipherString = lazySodium.encodeToString(cipher);
        assertThrows(IllegalArgumentException.class, () -> secretStreamLazy.cryptoSecretStreamPull(state, cipherString.substring(cipherString.length() - 2), null));
        assertThrows(IllegalArgumentException.class, () -> secretStreamLazy.cryptoSecretStreamPull(state, cipherString, new byte[0]));
    }
}
