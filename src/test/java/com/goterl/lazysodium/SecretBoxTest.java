/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.SecretBox;
import com.goterl.lazysodium.utils.DetachedEncrypt;
import com.goterl.lazysodium.utils.Key;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SecretBoxTest extends BaseTest {
    private static final String MESSAGE = "This is a super secret message.";
    private static final byte[] MESSAGE_BYTES = MESSAGE.getBytes(StandardCharsets.UTF_8);
    private static final String CIPHER = "0F0997960666C97163633D02A270A49B6A4A4D66BBE63911ADE9E7FE042BEF45A5C671DCBAD26999FF34770DEAC6E7";
    private static final byte[] CIPHER_BYTES = LazySodium.toBin(CIPHER);
    private static final byte[] CIPHER_DETACHED_BYTES = LazySodium.toBin(CIPHER.substring(SecretBox.MACBYTES * 2));
    private static final byte[] MAC_DETACHED_BYTES = LazySodium.toBin(CIPHER.substring(0, SecretBox.MACBYTES * 2));
    private static final String CIPHER_TAMPERED = "0F0997960666C97163633D02A270A49B6A4A4D66BBE63911ADE9E7FE042BEF45A5C671DCBAD26989FF34770DEAC6E7";
    private static final byte[] CIPHER_TAMPERED_BYTES = LazySodium.toBin(CIPHER_TAMPERED);
    private static final byte[] CIPHER_TAMPERED_DETACHED_BYTES = LazySodium.toBin(CIPHER_TAMPERED.substring(SecretBox.MACBYTES * 2));
    private static final byte[] MAC_TAMPERED_DETACHED_BYTES = LazySodium.toBin(CIPHER_TAMPERED.substring(0, SecretBox.MACBYTES * 2));
    private static final byte[] KEY_BYTES = LazySodium.toBin("4261DB611A20F8AE99AAE0CD94F8755A5D645D2502010D82C480C81D6A0D69F8");
    private static final byte[] NONCE_BYTES = LazySodium.toBin("7C7CA0FE472A6625F23E2E098214B453AF824EE992A46E02");

    private SecretBox.Lazy secretBoxLazy;
    private SecretBox.Native secretBoxNative;

    @BeforeAll
    public void before() {
        secretBoxLazy = lazySodium;
        secretBoxNative = lazySodium;
    }

    @Test
    public void encryptAndDecryptNative() {
        // Generate a symmetric key to encrypt the message.
        byte[] key = new byte[SecretBox.KEYBYTES];
        secretBoxNative.cryptoSecretBoxKeygen(key);

        byte[] nonce = lazySodium.nonce(SecretBox.NONCEBYTES);
        byte[] cipherBytes = new byte[MESSAGE_BYTES.length + SecretBox.MACBYTES];
        assertTrue(secretBoxNative.cryptoSecretBoxEasy(cipherBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, nonce, key));
        byte[] decryptedBytes = new byte[MESSAGE_BYTES.length];
        assertTrue(secretBoxNative.cryptoSecretBoxOpenEasy(decryptedBytes, cipherBytes, cipherBytes.length, nonce, key));

        assertArrayEquals(MESSAGE_BYTES, decryptedBytes);
    }

    @Test
    public void encryptAndDecryptNativeXChaCha20Poly1305() {
        // Generate a symmetric key to encrypt the message.
        byte[] key = new byte[SecretBox.KEYBYTES];
        secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Keygen(key);

        byte[] nonce = lazySodium.nonce(SecretBox.XCHACHA20POLY1305_NONCEBYTES);
        byte[] cipherBytes = new byte[MESSAGE_BYTES.length + SecretBox.XCHACHA20POLY1305_MACBYTES];
        assertTrue(secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Easy(cipherBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, nonce, key));
        byte[] decryptedBytes = new byte[MESSAGE_BYTES.length];
        assertTrue(secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenEasy(decryptedBytes, cipherBytes, cipherBytes.length, nonce, key));

        assertArrayEquals(MESSAGE_BYTES, decryptedBytes);
    }

    @Test
    public void cannotDecryptSalsaWithChaCha() {
        // Generate a symmetric key to encrypt the message.
        byte[] key = new byte[SecretBox.KEYBYTES];
        secretBoxNative.cryptoSecretBoxKeygen(key);

        byte[] nonce = lazySodium.nonce(SecretBox.NONCEBYTES);
        byte[] cipherBytes = new byte[MESSAGE_BYTES.length + SecretBox.MACBYTES];
        assertTrue(secretBoxNative.cryptoSecretBoxEasy(cipherBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, nonce, key));
        byte[] decryptedBytes = new byte[MESSAGE_BYTES.length];
        assertFalse(secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenEasy(decryptedBytes, cipherBytes, cipherBytes.length, nonce, key));
    }

    @Test
    public void encryptAndDecryptLazy() throws SodiumException {
        // Generate a symmetric key to encrypt the message.
        Key key = secretBoxLazy.cryptoSecretBoxKeygen();

        // Generate a random nonce.
        byte[] nonce = lazySodium.nonce(SecretBox.NONCEBYTES);
        String cipher = secretBoxLazy.cryptoSecretBoxEasy(MESSAGE, nonce, key);
        String decrypted = secretBoxLazy.cryptoSecretBoxOpenEasy(cipher, nonce, key);

        assertEquals(MESSAGE, decrypted);
    }

    @Test
    public void encryptAndDecryptDetachedNative() {
        byte[] cipherBytes = new byte[MESSAGE_BYTES.length];
        byte[] macBytes = new byte[SecretBox.MACBYTES];
        assertTrue(secretBoxNative.cryptoSecretBoxDetached(cipherBytes, macBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, KEY_BYTES));
        byte[] decryptedBytes = new byte[cipherBytes.length];
        assertTrue(secretBoxNative.cryptoSecretBoxOpenDetached(decryptedBytes, cipherBytes, macBytes, cipherBytes.length, NONCE_BYTES, KEY_BYTES));

        assertArrayEquals(MESSAGE_BYTES, decryptedBytes);

        // fail when MAC is wrong
        macBytes[macBytes.length / 2] ^= 0x40;
        assertFalse(secretBoxNative.cryptoSecretBoxOpenDetached(decryptedBytes, cipherBytes, macBytes, cipherBytes.length, NONCE_BYTES, KEY_BYTES));
    }

    @Test
    public void encryptAndDecryptXChaCha20Poly1305DetachedNative() {
        byte[] cipherBytes = new byte[MESSAGE_BYTES.length];
        byte[] macBytes = new byte[SecretBox.MACBYTES];
        assertTrue(secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Detached(cipherBytes, macBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, KEY_BYTES));
        byte[] decryptedBytes = new byte[cipherBytes.length];
        assertTrue(secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenDetached(decryptedBytes, cipherBytes, macBytes, cipherBytes.length, NONCE_BYTES, KEY_BYTES));

        assertArrayEquals(MESSAGE_BYTES, decryptedBytes);

        // fail when MAC is wrong
        macBytes[macBytes.length / 2] ^= 0x40;
        assertFalse(secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenDetached(decryptedBytes, cipherBytes, macBytes, cipherBytes.length, NONCE_BYTES, KEY_BYTES));
    }

    @Test
    public void encryptAndDecryptDetachedLazy() throws SodiumException {
        Key key = Key.fromBytes(KEY_BYTES);
        byte[] nonce = NONCE_BYTES;
        DetachedEncrypt detachedEncrypt = secretBoxLazy.cryptoSecretBoxDetached(MESSAGE, nonce, key);
        String decrypted = secretBoxLazy.cryptoSecretBoxOpenDetached(detachedEncrypt, nonce, key);

        assertEquals(MESSAGE, decrypted);
    }

    @Test
    public void cryptoSecretBoxKeygenLazy() {
        Key key = secretBoxLazy.cryptoSecretBoxKeygen();

        assertEquals(SecretBox.KEYBYTES, key.getAsBytes().length);
    }

    @Test
    public void cryptoSecretBoxOpenEasyLazy() throws SodiumException {
        String decrypted = secretBoxLazy.cryptoSecretBoxOpenEasy(CIPHER, NONCE_BYTES, Key.fromBytes(KEY_BYTES));
        assertEquals(MESSAGE, decrypted);
    }

    @Test
    public void refuseBadSignatureLazy() {
        assertThrows(SodiumException.class, () -> secretBoxLazy.cryptoSecretBoxOpenEasy(CIPHER_TAMPERED, NONCE_BYTES, Key.fromBytes(KEY_BYTES)));
    }

    @Test
    public void cryptoSecretBoxOpenEasyNative() {
        byte[] decryptedBytes = new byte[CIPHER_BYTES.length - SecretBox.MACBYTES];
        boolean success = secretBoxNative.cryptoSecretBoxOpenEasy(decryptedBytes, CIPHER_BYTES, CIPHER_BYTES.length, NONCE_BYTES, KEY_BYTES);
        assertTrue(success);
        assertArrayEquals(MESSAGE.getBytes(StandardCharsets.UTF_8), decryptedBytes);
    }

    @Test
    public void refuseBadSignatureNative() {
        assertFalse(secretBoxNative.cryptoSecretBoxOpenEasy(new byte[CIPHER_TAMPERED_BYTES.length - SecretBox.MACBYTES], CIPHER_TAMPERED_BYTES, CIPHER_TAMPERED_BYTES.length, NONCE_BYTES, KEY_BYTES));
    }

    @Test
    public void cryptoSecretBoxOpenDetachedLazy() throws SodiumException {
        String decrypted = secretBoxLazy.cryptoSecretBoxOpenDetached(new DetachedEncrypt(CIPHER_DETACHED_BYTES, MAC_DETACHED_BYTES), NONCE_BYTES, Key.fromBytes(KEY_BYTES));
        assertEquals(MESSAGE, decrypted);
    }

    @Test
    public void refuseBadSignatureDetachedLazy() {
        assertThrows(SodiumException.class, () -> secretBoxLazy.cryptoSecretBoxOpenDetached(new DetachedEncrypt(CIPHER_TAMPERED_DETACHED_BYTES, MAC_TAMPERED_DETACHED_BYTES), NONCE_BYTES, Key.fromBytes(KEY_BYTES)));
    }

    @Test
    public void cryptoSecretBoxKeygenNativeChecks() {
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxKeygen(new byte[SecretBox.KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxKeygen(new byte[SecretBox.KEYBYTES + 1]));
    }

    @Test
    public void cryptoSecretBoxEasyNativeChecks() {
        byte[] cipherBytes = new byte[MESSAGE_BYTES.length + SecretBox.MACBYTES];
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxEasy(cipherBytes, MESSAGE_BYTES, -1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxEasy(cipherBytes, MESSAGE_BYTES, MESSAGE_BYTES.length + 1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxEasy(new byte[MESSAGE_BYTES.length + SecretBox.MACBYTES - 1], MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxEasy(new byte[MESSAGE_BYTES.length + SecretBox.MACBYTES + 1], MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxEasy(cipherBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, new byte[SecretBox.NONCEBYTES - 1], KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxEasy(cipherBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, new byte[SecretBox.NONCEBYTES + 1], KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxEasy(cipherBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, new byte[SecretBox.KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxEasy(cipherBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, new byte[SecretBox.KEYBYTES + 1]));
    }

    @Test
    public void cryptoSecretBoxEasyLazyChecks() {
        Key key = Key.fromBytes(KEY_BYTES);
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxEasy(MESSAGE, new byte[SecretBox.NONCEBYTES - 1], key));
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxEasy(MESSAGE, new byte[SecretBox.NONCEBYTES + 1], key));
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxEasy(MESSAGE, NONCE_BYTES, Key.fromBytes(new byte[SecretBox.KEYBYTES - 1])));
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxEasy(MESSAGE, NONCE_BYTES, Key.fromBytes(new byte[SecretBox.KEYBYTES + 1])));
    }

    @Test
    public void cryptoSecretBoxOpenEasyLazyChecks() {
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxOpenEasy(lazySodium.encodeToString(new byte[SecretBox.MACBYTES - 1]), NONCE_BYTES, Key.fromBytes(KEY_BYTES)));
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxOpenEasy(CIPHER, new byte[SecretBox.NONCEBYTES - 1], Key.fromBytes(KEY_BYTES)));
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxOpenEasy(CIPHER, new byte[SecretBox.NONCEBYTES + 1], Key.fromBytes(KEY_BYTES)));
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxOpenEasy(CIPHER, NONCE_BYTES, Key.fromBytes(new byte[SecretBox.KEYBYTES - 1])));
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxOpenEasy(CIPHER, NONCE_BYTES, Key.fromBytes(new byte[SecretBox.KEYBYTES + 1])));
    }

    @Test
    public void cryptoSecretBoxOpenEasyNativeChecks() {
        byte[] decryptedBytes = new byte[CIPHER_BYTES.length - SecretBox.MACBYTES];
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenEasy(decryptedBytes, CIPHER_BYTES, -1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenEasy(decryptedBytes, CIPHER_BYTES, CIPHER_BYTES.length + 1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenEasy(decryptedBytes, CIPHER_BYTES, SecretBox.MACBYTES - 1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenEasy(new byte[CIPHER_BYTES.length - SecretBox.MACBYTES - 1], CIPHER_BYTES, CIPHER_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenEasy(new byte[CIPHER_BYTES.length - SecretBox.MACBYTES + 1], CIPHER_BYTES, CIPHER_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenEasy(decryptedBytes, CIPHER_BYTES, CIPHER_BYTES.length, new byte[SecretBox.NONCEBYTES - 1], KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenEasy(decryptedBytes, CIPHER_BYTES, CIPHER_BYTES.length, new byte[SecretBox.NONCEBYTES + 1], KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenEasy(decryptedBytes, CIPHER_BYTES, CIPHER_BYTES.length, NONCE_BYTES, new byte[SecretBox.KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenEasy(decryptedBytes, CIPHER_BYTES, CIPHER_BYTES.length, NONCE_BYTES, new byte[SecretBox.KEYBYTES + 1]));
    }

    @Test
    public void cryptoSecretBoxDetachedNativeChecks() {
        byte[] cipherBytes = new byte[MESSAGE_BYTES.length];
        byte[] macBytes = new byte[SecretBox.MACBYTES];
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxDetached(cipherBytes, macBytes, MESSAGE_BYTES, -1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxDetached(cipherBytes, macBytes, MESSAGE_BYTES, MESSAGE_BYTES.length + 1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxDetached(new byte[MESSAGE_BYTES.length - 1], macBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxDetached(new byte[MESSAGE_BYTES.length + 1], macBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxDetached(cipherBytes, new byte[SecretBox.MACBYTES - 1], MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxDetached(cipherBytes, new byte[SecretBox.MACBYTES + 1], MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxDetached(cipherBytes, macBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, new byte[SecretBox.NONCEBYTES - 1], KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxDetached(cipherBytes, macBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, new byte[SecretBox.NONCEBYTES + 1], KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxDetached(cipherBytes, macBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, new byte[SecretBox.KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxDetached(cipherBytes, macBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, new byte[SecretBox.KEYBYTES + 1]));
    }

    @Test
    public void cryptoSecretBoxDetachedLazyChecks() {
        Key key = Key.fromBytes(KEY_BYTES);
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxDetached(MESSAGE, new byte[SecretBox.NONCEBYTES - 1], key));
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxDetached(MESSAGE, new byte[SecretBox.NONCEBYTES + 1], key));
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxDetached(MESSAGE, NONCE_BYTES, Key.fromBytes(new byte[SecretBox.KEYBYTES - 1])));
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxDetached(MESSAGE, NONCE_BYTES, Key.fromBytes(new byte[SecretBox.KEYBYTES + 1])));
    }

    @Test
    public void cryptoSecretBoxOpenDetachedNativeChecks() {
        byte[] messageBytes = new byte[MESSAGE_BYTES.length];
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenDetached(messageBytes, CIPHER_BYTES, MAC_DETACHED_BYTES, -1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenDetached(messageBytes, CIPHER_BYTES, MAC_DETACHED_BYTES, CIPHER_BYTES.length + 1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenDetached(new byte[MESSAGE_BYTES.length - 1], CIPHER_BYTES, MAC_DETACHED_BYTES, CIPHER_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenDetached(new byte[MESSAGE_BYTES.length + 1], CIPHER_BYTES, MAC_DETACHED_BYTES, CIPHER_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenDetached(messageBytes, CIPHER_BYTES, new byte[SecretBox.MACBYTES - 1], CIPHER_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenDetached(messageBytes, CIPHER_BYTES, new byte[SecretBox.MACBYTES + 1], CIPHER_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenDetached(messageBytes, CIPHER_BYTES, MAC_DETACHED_BYTES, CIPHER_BYTES.length, new byte[SecretBox.NONCEBYTES - 1], KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenDetached(messageBytes, CIPHER_BYTES, MAC_DETACHED_BYTES, CIPHER_BYTES.length, new byte[SecretBox.NONCEBYTES + 1], KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenDetached(messageBytes, CIPHER_BYTES, MAC_DETACHED_BYTES, CIPHER_BYTES.length, NONCE_BYTES, new byte[SecretBox.KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxOpenDetached(messageBytes, CIPHER_BYTES, MAC_DETACHED_BYTES, CIPHER_BYTES.length, NONCE_BYTES, new byte[SecretBox.KEYBYTES + 1]));
    }

    @Test
    public void cryptoSecretBoxOpenDetachedLazyChecks() {
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxOpenDetached(new DetachedEncrypt(CIPHER_DETACHED_BYTES, new byte[SecretBox.MACBYTES - 1]), NONCE_BYTES, Key.fromBytes(KEY_BYTES)));
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxOpenDetached(new DetachedEncrypt(CIPHER_DETACHED_BYTES, new byte[SecretBox.MACBYTES + 1]), NONCE_BYTES, Key.fromBytes(KEY_BYTES)));
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxOpenDetached(new DetachedEncrypt(CIPHER_DETACHED_BYTES, MAC_DETACHED_BYTES), new byte[SecretBox.NONCEBYTES - 1], Key.fromBytes(KEY_BYTES)));
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxOpenDetached(new DetachedEncrypt(CIPHER_DETACHED_BYTES, MAC_DETACHED_BYTES), new byte[SecretBox.NONCEBYTES + 1], Key.fromBytes(KEY_BYTES)));
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxOpenDetached(new DetachedEncrypt(CIPHER_DETACHED_BYTES, MAC_DETACHED_BYTES), NONCE_BYTES, Key.fromBytes(new byte[SecretBox.KEYBYTES - 1])));
        assertThrows(IllegalArgumentException.class, () -> secretBoxLazy.cryptoSecretBoxOpenDetached(new DetachedEncrypt(CIPHER_DETACHED_BYTES, MAC_DETACHED_BYTES), NONCE_BYTES, Key.fromBytes(new byte[SecretBox.KEYBYTES + 1])));
    }

    @Test
    public void cryptoSecretBoxXChaCha20Poly1305KeygenNativeChecks() {
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Keygen(new byte[SecretBox.XCHACHA20POLY1305_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Keygen(new byte[SecretBox.XCHACHA20POLY1305_KEYBYTES + 1]));
    }

    @Test
    public void cryptoSecretBoxXChaCha20Poly1305EasyNativeChecks() {
        byte[] cipherBytes = new byte[MESSAGE_BYTES.length + SecretBox.MACBYTES];
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Easy(cipherBytes, MESSAGE_BYTES, -1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Easy(cipherBytes, MESSAGE_BYTES, MESSAGE_BYTES.length + 1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Easy(new byte[MESSAGE_BYTES.length + SecretBox.XCHACHA20POLY1305_MACBYTES - 1], MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Easy(new byte[MESSAGE_BYTES.length + SecretBox.XCHACHA20POLY1305_MACBYTES + 1], MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Easy(cipherBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, new byte[SecretBox.XCHACHA20POLY1305_NONCEBYTES - 1], KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Easy(cipherBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, new byte[SecretBox.XCHACHA20POLY1305_NONCEBYTES + 1], KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Easy(cipherBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, new byte[SecretBox.XCHACHA20POLY1305_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Easy(cipherBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, new byte[SecretBox.XCHACHA20POLY1305_KEYBYTES + 1]));
    }

    @Test
    public void cryptoSecretBoxXChaCha20Poly1305OpenEasyNativeChecks() {
        byte[] decryptedBytes = new byte[CIPHER_BYTES.length - SecretBox.MACBYTES];
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenEasy(decryptedBytes, CIPHER_BYTES, -1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenEasy(decryptedBytes, CIPHER_BYTES, CIPHER_BYTES.length + 1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenEasy(decryptedBytes, CIPHER_BYTES, SecretBox.XCHACHA20POLY1305_MACBYTES - 1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenEasy(new byte[CIPHER_BYTES.length - SecretBox.XCHACHA20POLY1305_MACBYTES - 1], CIPHER_BYTES, CIPHER_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenEasy(new byte[CIPHER_BYTES.length - SecretBox.XCHACHA20POLY1305_MACBYTES + 1], CIPHER_BYTES, CIPHER_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenEasy(decryptedBytes, CIPHER_BYTES, CIPHER_BYTES.length, new byte[SecretBox.XCHACHA20POLY1305_NONCEBYTES - 1], KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenEasy(decryptedBytes, CIPHER_BYTES, CIPHER_BYTES.length, new byte[SecretBox.XCHACHA20POLY1305_NONCEBYTES + 1], KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenEasy(decryptedBytes, CIPHER_BYTES, CIPHER_BYTES.length, NONCE_BYTES, new byte[SecretBox.XCHACHA20POLY1305_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenEasy(decryptedBytes, CIPHER_BYTES, CIPHER_BYTES.length, NONCE_BYTES, new byte[SecretBox.XCHACHA20POLY1305_KEYBYTES + 1]));
    }

    @Test
    public void cryptoSecretBoxXChaCha20Poly1305DetachedNativeChecks() {
        byte[] cipherBytes = new byte[MESSAGE_BYTES.length];
        byte[] macBytes = new byte[SecretBox.MACBYTES];
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Detached(cipherBytes, macBytes, MESSAGE_BYTES, -1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Detached(cipherBytes, macBytes, MESSAGE_BYTES, MESSAGE_BYTES.length + 1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Detached(new byte[MESSAGE_BYTES.length - 1], macBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Detached(new byte[MESSAGE_BYTES.length + 1], macBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Detached(cipherBytes, new byte[SecretBox.MACBYTES - 1], MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Detached(cipherBytes, new byte[SecretBox.MACBYTES + 1], MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Detached(cipherBytes, macBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, new byte[SecretBox.NONCEBYTES - 1], KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Detached(cipherBytes, macBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, new byte[SecretBox.NONCEBYTES + 1], KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Detached(cipherBytes, macBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, new byte[SecretBox.KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305Detached(cipherBytes, macBytes, MESSAGE_BYTES, MESSAGE_BYTES.length, NONCE_BYTES, new byte[SecretBox.KEYBYTES + 1]));
    }

    @Test
    public void cryptoSecretBoxXChaCha20Poly1305OpenDetachedNativeChecks() {
        byte[] messageBytes = new byte[MESSAGE_BYTES.length];
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenDetached(messageBytes, CIPHER_BYTES, MAC_DETACHED_BYTES, -1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenDetached(messageBytes, CIPHER_BYTES, MAC_DETACHED_BYTES, CIPHER_BYTES.length + 1, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenDetached(new byte[MESSAGE_BYTES.length - 1], CIPHER_BYTES, MAC_DETACHED_BYTES, CIPHER_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenDetached(new byte[MESSAGE_BYTES.length + 1], CIPHER_BYTES, MAC_DETACHED_BYTES, CIPHER_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenDetached(messageBytes, CIPHER_BYTES, new byte[SecretBox.XCHACHA20POLY1305_MACBYTES - 1], CIPHER_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenDetached(messageBytes, CIPHER_BYTES, new byte[SecretBox.XCHACHA20POLY1305_MACBYTES + 1], CIPHER_BYTES.length, NONCE_BYTES, KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenDetached(messageBytes, CIPHER_BYTES, MAC_DETACHED_BYTES, CIPHER_BYTES.length, new byte[SecretBox.XCHACHA20POLY1305_NONCEBYTES - 1], KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenDetached(messageBytes, CIPHER_BYTES, MAC_DETACHED_BYTES, CIPHER_BYTES.length, new byte[SecretBox.XCHACHA20POLY1305_NONCEBYTES + 1], KEY_BYTES));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenDetached(messageBytes, CIPHER_BYTES, MAC_DETACHED_BYTES, CIPHER_BYTES.length, NONCE_BYTES, new byte[SecretBox.XCHACHA20POLY1305_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> secretBoxNative.cryptoSecretBoxXChaCha20Poly1305OpenDetached(messageBytes, CIPHER_BYTES, MAC_DETACHED_BYTES, CIPHER_BYTES.length, NONCE_BYTES, new byte[SecretBox.XCHACHA20POLY1305_KEYBYTES + 1]));
    }
}
