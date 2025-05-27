/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.interfaces.AEAD;
import com.goterl.lazysodium.interfaces.MessageEncoder;
import com.goterl.lazysodium.utils.DetachedDecrypt;
import com.goterl.lazysodium.utils.DetachedEncrypt;
import com.goterl.lazysodium.utils.HexMessageEncoder;
import com.goterl.lazysodium.utils.Key;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class AEADTest extends BaseTest {
    private final String PASSWORD = "superSecurePassword";
    private final MessageEncoder encoder = new HexMessageEncoder();

    private AEAD.Lazy aeadLazy;
    private AEAD.Native aeadNative;

    @BeforeAll
    public void before() {
        aeadLazy = lazySodium;
        aeadNative = lazySodium;
    }

    @Test
    public void encryptChacha() throws AEADBadTagException {
        Key key = aeadLazy.keygen(AEAD.Method.CHACHA20_POLY1305);
        byte[] nPub = lazySodium.nonce(AEAD.CHACHA20POLY1305_NPUBBYTES);

        String cipher = aeadLazy.encrypt(PASSWORD, null, nPub, key, AEAD.Method.CHACHA20_POLY1305);
        String decrypted = aeadLazy.decrypt(cipher, null, nPub, key, AEAD.Method.CHACHA20_POLY1305);

        assertEquals(decrypted, PASSWORD);
    }

    @Test
    public void encryptChachaMalformedCipher() {
        Key key = aeadLazy.keygen(AEAD.Method.CHACHA20_POLY1305);
        byte[] nPub = lazySodium.nonce(AEAD.CHACHA20POLY1305_NPUBBYTES);
        String cipher = aeadLazy.encrypt(PASSWORD, null, nPub, key, AEAD.Method.CHACHA20_POLY1305);

        assertThrows(AEADBadTagException.class, () -> aeadLazy.decrypt(malformCipher(cipher), null, nPub, key, AEAD.Method.CHACHA20_POLY1305));
    }

    @Test
    public void encryptChachaIetf() throws AEADBadTagException {
        Key key = aeadLazy.keygen(AEAD.Method.CHACHA20_POLY1305_IETF);

        byte[] nPub = lazySodium.nonce(AEAD.CHACHA20POLY1305_IETF_NPUBBYTES);

        String cipher = aeadLazy.encrypt(PASSWORD, null, nPub, key, AEAD.Method.CHACHA20_POLY1305_IETF);
        String decrypted = aeadLazy.decrypt(cipher, null, nPub, key, AEAD.Method.CHACHA20_POLY1305_IETF);

        assertEquals(decrypted, PASSWORD);
    }

    @Test
    public void encryptChachaIetfMalformedCipher() {
        Key key = aeadLazy.keygen(AEAD.Method.CHACHA20_POLY1305_IETF);
        byte[] nPub = lazySodium.nonce(AEAD.CHACHA20POLY1305_IETF_NPUBBYTES);
        String cipher = aeadLazy.encrypt(PASSWORD, null, nPub, key, AEAD.Method.CHACHA20_POLY1305_IETF);

        assertThrows(AEADBadTagException.class, () -> aeadLazy.decrypt(malformCipher(cipher), null, nPub, key, AEAD.Method.CHACHA20_POLY1305_IETF));
    }

    @Test
    public void encryptXChacha() throws AEADBadTagException {
        Key key = aeadLazy.keygen(AEAD.Method.XCHACHA20_POLY1305_IETF);

        byte[] nPub = lazySodium.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES);

        String cipher = aeadLazy.encrypt(PASSWORD, null, nPub, key, AEAD.Method.XCHACHA20_POLY1305_IETF);
        String decrypted = aeadLazy.decrypt(cipher, null, nPub, key, AEAD.Method.XCHACHA20_POLY1305_IETF);

        assertEquals(decrypted, PASSWORD);
    }

    @Test
    public void encryptXChachaMalformedCipher() {
        Key key = aeadLazy.keygen(AEAD.Method.XCHACHA20_POLY1305_IETF);
        byte[] nPub = lazySodium.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES);
        String cipher = aeadLazy.encrypt(PASSWORD, null, nPub, key, AEAD.Method.XCHACHA20_POLY1305_IETF);

        assertThrows(AEADBadTagException.class, () -> aeadLazy.decrypt(malformCipher(cipher), null, nPub, key, AEAD.Method.XCHACHA20_POLY1305_IETF));
    }

    @Test
    public void encryptChachaDetached() throws AEADBadTagException {
        Key key = aeadLazy.keygen(AEAD.Method.CHACHA20_POLY1305);

        byte[] nPub = lazySodium.nonce(AEAD.CHACHA20POLY1305_NPUBBYTES);

        DetachedEncrypt detachedEncrypt
                = aeadLazy.encryptDetached(PASSWORD, null, nPub, key, AEAD.Method.CHACHA20_POLY1305);

        DetachedDecrypt detachedDecrypt = aeadLazy.decryptDetached(detachedEncrypt, null, nPub, key, AEAD.Method.CHACHA20_POLY1305);

        assertEquals(detachedDecrypt.getMessageString(), PASSWORD);
    }

    @Test
    public void encryptChachaDetachedMalformedCipher() {
        Key key = aeadLazy.keygen(AEAD.Method.CHACHA20_POLY1305);
        byte[] nPub = lazySodium.nonce(AEAD.CHACHA20POLY1305_NPUBBYTES);
        DetachedEncrypt detachedEncrypt = aeadLazy.encryptDetached(PASSWORD, null, nPub, key, AEAD.Method.CHACHA20_POLY1305);
        DetachedEncrypt malformed = new DetachedEncrypt(malformCipherBytes(detachedEncrypt.getCipherString()), detachedEncrypt.getMac());

        assertThrows(AEADBadTagException.class, () -> aeadLazy.decryptDetached(malformed, null, nPub, key, AEAD.Method.CHACHA20_POLY1305));
    }

    @Test
    public void encryptChachaIetfDetached() throws AEADBadTagException {
        Key key = aeadLazy.keygen(AEAD.Method.CHACHA20_POLY1305_IETF);
        byte[] nPub = lazySodium.nonce(AEAD.CHACHA20POLY1305_IETF_NPUBBYTES);

        DetachedEncrypt detachedEncrypt
                = aeadLazy.encryptDetached(PASSWORD, null, nPub, key, AEAD.Method.CHACHA20_POLY1305_IETF);
        DetachedDecrypt detachedDecrypt = aeadLazy.decryptDetached(detachedEncrypt, null, nPub, key, AEAD.Method.CHACHA20_POLY1305_IETF);
        assertEquals(detachedDecrypt.getMessageString(), PASSWORD);
    }

    @Test
    public void encryptChachaIetfDetachedMalformedCipher() {
        Key key = aeadLazy.keygen(AEAD.Method.CHACHA20_POLY1305_IETF);
        byte[] nPub = lazySodium.nonce(AEAD.CHACHA20POLY1305_IETF_NPUBBYTES);

        DetachedEncrypt detachedEncrypt = aeadLazy.encryptDetached(PASSWORD, null, nPub, key, AEAD.Method.CHACHA20_POLY1305_IETF);
        DetachedEncrypt malformed = new DetachedEncrypt(malformCipherBytes(detachedEncrypt.getCipherString()), detachedEncrypt.getMac());

        assertThrows(AEADBadTagException.class, () -> aeadLazy.decryptDetached(malformed, null, nPub, key, AEAD.Method.CHACHA20_POLY1305_IETF));
    }

    @Test
    public void encryptXChachaDetached() throws AEADBadTagException {
        Key key = aeadLazy.keygen(AEAD.Method.XCHACHA20_POLY1305_IETF);
        byte[] nPub = lazySodium.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES);

        DetachedEncrypt detachedEncrypt
                = aeadLazy.encryptDetached(PASSWORD, null, nPub, key, AEAD.Method.XCHACHA20_POLY1305_IETF);

        DetachedDecrypt detachedDecrypt = aeadLazy.decryptDetached(detachedEncrypt, null, nPub, key, AEAD.Method.XCHACHA20_POLY1305_IETF);
        assertEquals(detachedDecrypt.getMessageString(), PASSWORD);
    }

    @Test
    public void encryptXChachaDetachedMalformedCipher() {
        Key key = aeadLazy.keygen(AEAD.Method.XCHACHA20_POLY1305_IETF);
        byte[] nPub = lazySodium.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES);

        DetachedEncrypt detachedEncrypt
                = aeadLazy.encryptDetached(PASSWORD, null, nPub, key, AEAD.Method.XCHACHA20_POLY1305_IETF);
        DetachedEncrypt malformed = new DetachedEncrypt(malformCipherBytes(detachedEncrypt.getCipherString()), detachedEncrypt.getMac());

        assertThrows(AEADBadTagException.class, () -> aeadLazy.decryptDetached(malformed, null, nPub, key, AEAD.Method.XCHACHA20_POLY1305_IETF));
    }


    @Test
    public void encryptAES() throws AEADBadTagException {
        if (!aeadNative.cryptoAeadAES256GCMIsAvailable()) {
            return;
        }

        Key key = aeadLazy.keygen(AEAD.Method.AES256GCM);

        byte[] nPub = lazySodium.nonce(AEAD.AES256GCM_NPUBBYTES);

        String cipher = aeadLazy.encrypt(PASSWORD, null, nPub, key, AEAD.Method.AES256GCM);
        String decrypted = aeadLazy.decrypt(cipher, null, nPub, key, AEAD.Method.AES256GCM);

        assertEquals(decrypted, PASSWORD);
    }

    @Test
    public void encryptAESMalformedCipher() {
        if (!aeadNative.cryptoAeadAES256GCMIsAvailable()) {
            return;
        }

        Key key = aeadLazy.keygen(AEAD.Method.AES256GCM);
        byte[] nPub = lazySodium.nonce(AEAD.AES256GCM_NPUBBYTES);
        String cipher = aeadLazy.encrypt(PASSWORD, null, nPub, key, AEAD.Method.AES256GCM);

        assertThrows(AEADBadTagException.class, () -> aeadLazy.decrypt(malformCipher(cipher), null, nPub, key, AEAD.Method.AES256GCM));
    }

    @Test
    public void encryptAESDetached() throws AEADBadTagException {
        if (!aeadNative.cryptoAeadAES256GCMIsAvailable()) {
            return;
        }

        Key key = aeadLazy.keygen(AEAD.Method.AES256GCM);
        byte[] nPub = lazySodium.nonce(AEAD.AES256GCM_NPUBBYTES);
        DetachedEncrypt detachedEncrypt
                = aeadLazy.encryptDetached(PASSWORD, null, nPub, key, AEAD.Method.AES256GCM);
        DetachedDecrypt detachedDecrypt = aeadLazy.decryptDetached(detachedEncrypt, null, nPub, key, AEAD.Method.AES256GCM);
        assertEquals(detachedDecrypt.getMessageString(), PASSWORD);
    }

    @Test
    public void encryptAESDetachedMalformedCipher() {
        if (!aeadNative.cryptoAeadAES256GCMIsAvailable()) {
            return;
        }

        Key key = aeadLazy.keygen(AEAD.Method.AES256GCM);
        byte[] nPub = lazySodium.nonce(AEAD.AES256GCM_NPUBBYTES);

        DetachedEncrypt detachedEncrypt
                = aeadLazy.encryptDetached(PASSWORD, null, nPub, key, AEAD.Method.AES256GCM);
        DetachedEncrypt malformed = new DetachedEncrypt(malformCipherBytes(detachedEncrypt.getCipherString()), detachedEncrypt.getMac());

        assertThrows(AEADBadTagException.class, () -> aeadLazy.decryptDetached(malformed, null, nPub, key, AEAD.Method.AES256GCM));
    }

    @Test
    public void cryptoAeadChaCha20Poly1305Keygen() {
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Keygen(new byte[AEAD.CHACHA20POLY1305_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Keygen(new byte[AEAD.CHACHA20POLY1305_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadChaCha20Poly1305EncryptChecks() {
        Key key = aeadLazy.keygen(AEAD.Method.CHACHA20_POLY1305);
        byte[] nPub = lazySodium.nonce(AEAD.CHACHA20POLY1305_NPUBBYTES);
        byte[] passwordBytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        byte[] cipherBytes = new byte[passwordBytes.length + AEAD.CHACHA20POLY1305_ABYTES];

        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Encrypt(cipherBytes, null, passwordBytes, -1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Encrypt(cipherBytes, null, passwordBytes, passwordBytes.length + 1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Encrypt(new byte[cipherBytes.length - 1], null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Encrypt(new byte[cipherBytes.length - 1], new long[1], passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Encrypt(new byte[cipherBytes.length + 1], null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Encrypt(cipherBytes, new long[0], passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Encrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, -1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Encrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Encrypt(cipherBytes, null, passwordBytes, passwordBytes.length, new byte[1], 2, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Encrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 0, new byte[AEAD.CHACHA20POLY1305_NPUBBYTES - 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Encrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 0, new byte[AEAD.CHACHA20POLY1305_NPUBBYTES + 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Encrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 0, nPub, new byte[AEAD.CHACHA20POLY1305_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Encrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 0, nPub, new byte[AEAD.CHACHA20POLY1305_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadChaCha20Poly1305DecryptChecks() {
        Key key = aeadLazy.keygen(AEAD.Method.CHACHA20_POLY1305);
        byte[] nPub = lazySodium.nonce(AEAD.CHACHA20POLY1305_NPUBBYTES);
        byte[] cipherBytes = new byte[PASSWORD.getBytes(StandardCharsets.UTF_8).length + AEAD.CHACHA20POLY1305_ABYTES];
        byte[] messageBytes = new byte[cipherBytes.length - AEAD.CHACHA20POLY1305_ABYTES];

        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Decrypt(messageBytes, null, cipherBytes, -1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Decrypt(messageBytes, null, cipherBytes, cipherBytes.length + 1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Decrypt(new byte[messageBytes.length - 1], null, cipherBytes, cipherBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Decrypt(new byte[messageBytes.length - 1], new long[1], cipherBytes, cipherBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Decrypt(new byte[messageBytes.length + 1], null, cipherBytes, cipherBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Decrypt(messageBytes, new long[0], cipherBytes, cipherBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Decrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, -1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Decrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Decrypt(messageBytes, null, cipherBytes, cipherBytes.length, new byte[1], 2, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Decrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 0, new byte[AEAD.CHACHA20POLY1305_NPUBBYTES - 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Decrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 0, new byte[AEAD.CHACHA20POLY1305_NPUBBYTES + 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Decrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 0, nPub, new byte[AEAD.CHACHA20POLY1305_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305Decrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 0, nPub, new byte[AEAD.CHACHA20POLY1305_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadChaCha20Poly1305EncryptDetachedChecks() {
        Key key = aeadLazy.keygen(AEAD.Method.CHACHA20_POLY1305);
        byte[] nPub = lazySodium.nonce(AEAD.CHACHA20POLY1305_NPUBBYTES);
        byte[] passwordBytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        byte[] cipherBytes = new byte[passwordBytes.length];
        byte[] mac = new byte[AEAD.CHACHA20POLY1305_ABYTES];

        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305EncryptDetached(cipherBytes, mac, null, passwordBytes, -1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305EncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length + 1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305EncryptDetached(new byte[cipherBytes.length - 1], mac, null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305EncryptDetached(new byte[cipherBytes.length + 1], mac, null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305EncryptDetached(cipherBytes, new byte[mac.length - 1], null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305EncryptDetached(cipherBytes, new byte[mac.length - 1], new long[1], passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305EncryptDetached(cipherBytes, new byte[mac.length + 1], null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305EncryptDetached(cipherBytes, mac, new long[0], passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305EncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, -1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305EncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305EncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, new byte[1], 2, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305EncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 0, new byte[AEAD.CHACHA20POLY1305_NPUBBYTES - 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305EncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 0, new byte[AEAD.CHACHA20POLY1305_NPUBBYTES + 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305EncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 0, nPub, new byte[AEAD.CHACHA20POLY1305_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305EncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 0, nPub, new byte[AEAD.CHACHA20POLY1305_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadChaCha20Poly1305DecryptDetachedChecks() {
        Key key = aeadLazy.keygen(AEAD.Method.CHACHA20_POLY1305);
        byte[] nPub = lazySodium.nonce(AEAD.CHACHA20POLY1305_NPUBBYTES);
        byte[] cipherBytes = new byte[PASSWORD.getBytes(StandardCharsets.UTF_8).length];
        byte[] mac = new byte[AEAD.CHACHA20POLY1305_ABYTES];
        byte[] messageBytes = new byte[cipherBytes.length];

        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305DecryptDetached(messageBytes, cipherBytes, -1, mac, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305DecryptDetached(messageBytes, cipherBytes, cipherBytes.length + 1, mac, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305DecryptDetached(new byte[messageBytes.length - 1], cipherBytes, cipherBytes.length, mac, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305DecryptDetached(new byte[messageBytes.length + 1], cipherBytes, cipherBytes.length, mac, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305DecryptDetached(messageBytes, cipherBytes, cipherBytes.length, new byte[AEAD.CHACHA20POLY1305_ABYTES - 1], null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305DecryptDetached(messageBytes, cipherBytes, cipherBytes.length, new byte[AEAD.CHACHA20POLY1305_ABYTES + 1], null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305DecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, -1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305DecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305DecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, new byte[1], 2, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305DecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 0, new byte[AEAD.CHACHA20POLY1305_NPUBBYTES - 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305DecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 0, new byte[AEAD.CHACHA20POLY1305_NPUBBYTES + 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305DecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 0, nPub, new byte[AEAD.CHACHA20POLY1305_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305DecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 0, nPub, new byte[AEAD.CHACHA20POLY1305_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadChaCha20Poly1305IetfKeygen() {
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfKeygen(new byte[AEAD.CHACHA20POLY1305_IETF_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfKeygen(new byte[AEAD.CHACHA20POLY1305_IETF_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadChaCha20Poly1305IetfEncryptChecks() {
        Key key = aeadLazy.keygen(AEAD.Method.CHACHA20_POLY1305_IETF);
        byte[] nPub = lazySodium.nonce(AEAD.CHACHA20POLY1305_IETF_NPUBBYTES);
        byte[] passwordBytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        byte[] cipherBytes = new byte[passwordBytes.length + AEAD.CHACHA20POLY1305_IETF_ABYTES];

        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, -1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length + 1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncrypt(new byte[cipherBytes.length - 1], null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncrypt(new byte[cipherBytes.length - 1], new long[1], passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncrypt(new byte[cipherBytes.length + 1], null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncrypt(cipherBytes, new long[0], passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, -1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, new byte[1], 2, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 0, new byte[AEAD.CHACHA20POLY1305_IETF_NPUBBYTES - 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 0, new byte[AEAD.CHACHA20POLY1305_IETF_NPUBBYTES + 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 0, nPub, new byte[AEAD.CHACHA20POLY1305_IETF_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 0, nPub, new byte[AEAD.CHACHA20POLY1305_IETF_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadChaCha20Poly1305IetfDecryptChecks() {
        Key key = aeadLazy.keygen(AEAD.Method.CHACHA20_POLY1305_IETF);
        byte[] nPub = lazySodium.nonce(AEAD.CHACHA20POLY1305_IETF_NPUBBYTES);
        byte[] cipherBytes = new byte[PASSWORD.getBytes(StandardCharsets.UTF_8).length + AEAD.CHACHA20POLY1305_IETF_ABYTES];
        byte[] messageBytes = new byte[cipherBytes.length - AEAD.CHACHA20POLY1305_IETF_ABYTES];

        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, -1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, cipherBytes.length + 1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecrypt(new byte[messageBytes.length - 1], null, cipherBytes, cipherBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecrypt(new byte[messageBytes.length - 1], new long[1], cipherBytes, cipherBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecrypt(new byte[messageBytes.length + 1], null, cipherBytes, cipherBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecrypt(messageBytes, new long[0], cipherBytes, cipherBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, -1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, new byte[1], 2, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 0, new byte[AEAD.CHACHA20POLY1305_IETF_NPUBBYTES - 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 0, new byte[AEAD.CHACHA20POLY1305_IETF_NPUBBYTES + 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 0, nPub, new byte[AEAD.CHACHA20POLY1305_IETF_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 0, nPub, new byte[AEAD.CHACHA20POLY1305_IETF_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadChaCha20Poly1305IetfEncryptDetachedChecks() {
        Key key = aeadLazy.keygen(AEAD.Method.CHACHA20_POLY1305_IETF);
        byte[] nPub = lazySodium.nonce(AEAD.CHACHA20POLY1305_IETF_NPUBBYTES);
        byte[] passwordBytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        byte[] cipherBytes = new byte[passwordBytes.length];
        byte[] mac = new byte[AEAD.CHACHA20POLY1305_IETF_ABYTES];

        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, -1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length + 1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncryptDetached(new byte[cipherBytes.length - 1], mac, null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncryptDetached(new byte[cipherBytes.length + 1], mac, null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncryptDetached(cipherBytes, new byte[mac.length - 1], null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncryptDetached(cipherBytes, new byte[mac.length - 1], new long[1], passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncryptDetached(cipherBytes, new byte[mac.length + 1], null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, new long[0], passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, -1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, new byte[1], 2, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 0, new byte[AEAD.CHACHA20POLY1305_IETF_NPUBBYTES - 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 0, new byte[AEAD.CHACHA20POLY1305_IETF_NPUBBYTES + 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 0, nPub, new byte[AEAD.CHACHA20POLY1305_IETF_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 0, nPub, new byte[AEAD.CHACHA20POLY1305_IETF_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadChaCha20Poly1305IetfDecryptDetachedChecks() {
        Key key = aeadLazy.keygen(AEAD.Method.CHACHA20_POLY1305_IETF);
        byte[] nPub = lazySodium.nonce(AEAD.CHACHA20POLY1305_IETF_NPUBBYTES);
        byte[] cipherBytes = new byte[PASSWORD.getBytes(StandardCharsets.UTF_8).length];
        byte[] mac = new byte[AEAD.CHACHA20POLY1305_IETF_ABYTES];
        byte[] messageBytes = new byte[cipherBytes.length];

        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, -1, mac, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length + 1, mac, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecryptDetached(new byte[messageBytes.length - 1], cipherBytes, cipherBytes.length, mac, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecryptDetached(new byte[messageBytes.length + 1], cipherBytes, cipherBytes.length, mac, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, new byte[AEAD.CHACHA20POLY1305_IETF_ABYTES - 1], null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, new byte[AEAD.CHACHA20POLY1305_IETF_ABYTES + 1], null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, -1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, new byte[1], 2, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 0, new byte[AEAD.CHACHA20POLY1305_IETF_NPUBBYTES - 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 0, new byte[AEAD.CHACHA20POLY1305_IETF_NPUBBYTES + 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 0, nPub, new byte[AEAD.CHACHA20POLY1305_IETF_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 0, nPub, new byte[AEAD.CHACHA20POLY1305_IETF_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadXChaCha20Poly1305IetfKeygen() {
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfKeygen(new byte[AEAD.XCHACHA20POLY1305_IETF_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfKeygen(new byte[AEAD.XCHACHA20POLY1305_IETF_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadXChaCha20Poly1305IetfEncryptChecks() {
        Key key = aeadLazy.keygen(AEAD.Method.XCHACHA20_POLY1305_IETF);
        byte[] nPub = lazySodium.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES);
        byte[] passwordBytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        byte[] cipherBytes = new byte[passwordBytes.length + AEAD.XCHACHA20POLY1305_IETF_ABYTES];

        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, -1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length + 1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncrypt(new byte[cipherBytes.length - 1], null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncrypt(new byte[cipherBytes.length - 1], new long[1], passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncrypt(new byte[cipherBytes.length + 1], null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncrypt(cipherBytes, new long[0], passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, -1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, new byte[1], 2, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 0, new byte[AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES - 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 0, new byte[AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES + 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 0, nPub, new byte[AEAD.XCHACHA20POLY1305_IETF_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 0, nPub, new byte[AEAD.XCHACHA20POLY1305_IETF_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadXChaCha20Poly1305IetfDecryptChecks() {
        Key key = aeadLazy.keygen(AEAD.Method.XCHACHA20_POLY1305_IETF);
        byte[] nPub = lazySodium.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES);
        byte[] cipherBytes = new byte[PASSWORD.getBytes(StandardCharsets.UTF_8).length + AEAD.XCHACHA20POLY1305_IETF_ABYTES];
        byte[] messageBytes = new byte[cipherBytes.length - AEAD.XCHACHA20POLY1305_IETF_ABYTES];

        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, -1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, cipherBytes.length + 1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecrypt(new byte[messageBytes.length - 1], null, cipherBytes, cipherBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecrypt(new byte[messageBytes.length - 1], new long[1], cipherBytes, cipherBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecrypt(new byte[messageBytes.length + 1], null, cipherBytes, cipherBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecrypt(messageBytes, new long[0], cipherBytes, cipherBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, -1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, new byte[1], 2, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 0, new byte[AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES - 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 0, new byte[AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES + 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 0, nPub, new byte[AEAD.XCHACHA20POLY1305_IETF_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 0, nPub, new byte[AEAD.XCHACHA20POLY1305_IETF_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadXChaCha20Poly1305IetfEncryptDetachedChecks() {
        Key key = aeadLazy.keygen(AEAD.Method.XCHACHA20_POLY1305_IETF);
        byte[] nPub = lazySodium.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES);
        byte[] passwordBytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        byte[] cipherBytes = new byte[passwordBytes.length];
        byte[] mac = new byte[AEAD.XCHACHA20POLY1305_IETF_ABYTES];

        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, -1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length + 1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncryptDetached(new byte[cipherBytes.length - 1], mac, null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncryptDetached(new byte[cipherBytes.length + 1], mac, null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncryptDetached(cipherBytes, new byte[mac.length - 1], null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncryptDetached(cipherBytes, new byte[mac.length - 1], new long[1], passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncryptDetached(cipherBytes, new byte[mac.length + 1], null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, new long[0], passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, -1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, new byte[1], 2, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 0, new byte[AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES - 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 0, new byte[AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES + 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 0, nPub, new byte[AEAD.XCHACHA20POLY1305_IETF_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 0, nPub, new byte[AEAD.XCHACHA20POLY1305_IETF_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadXChaCha20Poly1305IetfDecryptDetachedChecks() {
        Key key = aeadLazy.keygen(AEAD.Method.XCHACHA20_POLY1305_IETF);
        byte[] nPub = lazySodium.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES);
        byte[] cipherBytes = new byte[PASSWORD.getBytes(StandardCharsets.UTF_8).length];
        byte[] mac = new byte[AEAD.XCHACHA20POLY1305_IETF_ABYTES];
        byte[] messageBytes = new byte[cipherBytes.length];

        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, -1, mac, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length + 1, mac, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecryptDetached(new byte[messageBytes.length - 1], cipherBytes, cipherBytes.length, mac, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecryptDetached(new byte[messageBytes.length + 1], cipherBytes, cipherBytes.length, mac, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, new byte[AEAD.XCHACHA20POLY1305_IETF_ABYTES - 1], null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, new byte[AEAD.XCHACHA20POLY1305_IETF_ABYTES + 1], null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, -1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, new byte[1], 2, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 0, new byte[AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES - 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 0, new byte[AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES + 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 0, nPub, new byte[AEAD.XCHACHA20POLY1305_IETF_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadXChaCha20Poly1305IetfDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 0, nPub, new byte[AEAD.XCHACHA20POLY1305_IETF_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadAES256GCMKeygen() {
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMKeygen(new byte[AEAD.AES256GCM_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMKeygen(new byte[AEAD.AES256GCM_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadAES256GCMEncryptChecks() {
        Key key = aeadLazy.keygen(AEAD.Method.AES256GCM);
        byte[] nPub = lazySodium.nonce(AEAD.AES256GCM_NPUBBYTES);
        byte[] passwordBytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        byte[] cipherBytes = new byte[passwordBytes.length + AEAD.AES256GCM_ABYTES];

        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncrypt(cipherBytes, null, passwordBytes, -1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length + 1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncrypt(new byte[cipherBytes.length - 1], null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncrypt(new byte[cipherBytes.length - 1], new long[1], passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncrypt(new byte[cipherBytes.length + 1], null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncrypt(cipherBytes, new long[0], passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, -1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, new byte[1], 2, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 0, new byte[AEAD.AES256GCM_NPUBBYTES - 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 0, new byte[AEAD.AES256GCM_NPUBBYTES + 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 0, nPub, new byte[AEAD.AES256GCM_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncrypt(cipherBytes, null, passwordBytes, passwordBytes.length, null, 0, nPub, new byte[AEAD.AES256GCM_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadAES256GCMDecryptChecks() {
        Key key = aeadLazy.keygen(AEAD.Method.AES256GCM);
        byte[] nPub = lazySodium.nonce(AEAD.AES256GCM_NPUBBYTES);
        byte[] cipherBytes = new byte[PASSWORD.getBytes(StandardCharsets.UTF_8).length + AEAD.AES256GCM_ABYTES];
        byte[] messageBytes = new byte[cipherBytes.length - AEAD.AES256GCM_ABYTES];

        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecrypt(messageBytes, null, cipherBytes, -1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecrypt(messageBytes, null, cipherBytes, cipherBytes.length + 1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecrypt(new byte[messageBytes.length - 1], null, cipherBytes, cipherBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecrypt(new byte[messageBytes.length - 1], new long[1], cipherBytes, cipherBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecrypt(new byte[messageBytes.length + 1], null, cipherBytes, cipherBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecrypt(messageBytes, new long[0], cipherBytes, cipherBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, -1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, new byte[1], 2, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 0, new byte[AEAD.AES256GCM_NPUBBYTES - 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 0, new byte[AEAD.AES256GCM_NPUBBYTES + 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 0, nPub, new byte[AEAD.AES256GCM_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecrypt(messageBytes, null, cipherBytes, cipherBytes.length, null, 0, nPub, new byte[AEAD.AES256GCM_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadAES256GCMEncryptDetachedChecks() {
        Key key = aeadLazy.keygen(AEAD.Method.AES256GCM);
        byte[] nPub = lazySodium.nonce(AEAD.AES256GCM_NPUBBYTES);
        byte[] passwordBytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        byte[] cipherBytes = new byte[passwordBytes.length];
        byte[] mac = new byte[AEAD.AES256GCM_ABYTES];

        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncryptDetached(cipherBytes, mac, null, passwordBytes, -1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length + 1, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncryptDetached(new byte[cipherBytes.length - 1], mac, null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncryptDetached(new byte[cipherBytes.length + 1], mac, null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncryptDetached(cipherBytes, new byte[mac.length - 1], null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncryptDetached(cipherBytes, new byte[mac.length - 1], new long[1], passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncryptDetached(cipherBytes, new byte[mac.length + 1], null, passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncryptDetached(cipherBytes, mac, new long[0], passwordBytes, passwordBytes.length, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, -1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, new byte[1], 2, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 0, new byte[AEAD.AES256GCM_NPUBBYTES - 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 0, new byte[AEAD.AES256GCM_NPUBBYTES + 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 0, nPub, new byte[AEAD.AES256GCM_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMEncryptDetached(cipherBytes, mac, null, passwordBytes, passwordBytes.length, null, 0, nPub, new byte[AEAD.AES256GCM_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAeadAES256GCMDecryptDetachedChecks() {
        Key key = aeadLazy.keygen(AEAD.Method.AES256GCM);
        byte[] nPub = lazySodium.nonce(AEAD.AES256GCM_NPUBBYTES);
        byte[] cipherBytes = new byte[PASSWORD.getBytes(StandardCharsets.UTF_8).length];
        byte[] mac = new byte[AEAD.AES256GCM_ABYTES];
        byte[] messageBytes = new byte[cipherBytes.length];

        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecryptDetached(messageBytes, cipherBytes, -1, mac, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecryptDetached(messageBytes, cipherBytes, cipherBytes.length + 1, mac, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecryptDetached(new byte[messageBytes.length - 1], cipherBytes, cipherBytes.length, mac, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecryptDetached(new byte[messageBytes.length + 1], cipherBytes, cipherBytes.length, mac, null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, new byte[AEAD.AES256GCM_ABYTES - 1], null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, new byte[AEAD.AES256GCM_ABYTES + 1], null, 0, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, -1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 1, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, new byte[1], 2, nPub, key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 0, new byte[AEAD.AES256GCM_NPUBBYTES - 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 0, new byte[AEAD.AES256GCM_NPUBBYTES + 1], key.getAsBytes()));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 0, nPub, new byte[AEAD.AES256GCM_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> aeadNative.cryptoAeadAES256GCMDecryptDetached(messageBytes, cipherBytes, cipherBytes.length, mac, null, 0, nPub, new byte[AEAD.AES256GCM_KEYBYTES + 1]));
    }

    private String malformCipher(String ciphertext) {
        byte[] malformedBuf = malformCipherBytes(ciphertext);
        return encoder.encode(malformedBuf);
    }

    private byte[] malformCipherBytes(String ciphertext) {
        byte[] cipherBuf = encoder.decode(ciphertext);
        for (int i = 0; i < cipherBuf.length; i++) {
            cipherBuf[i] ^= (byte) 0xff;
        }
        return cipherBuf;
    }
}
