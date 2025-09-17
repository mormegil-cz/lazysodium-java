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
import com.goterl.lazysodium.utils.DetachedDecrypt;
import com.goterl.lazysodium.utils.DetachedEncrypt;
import com.goterl.lazysodium.utils.KeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests public and private key encryption.
 */
public class BoxTest extends BaseTest {

    private Box.Lazy cryptoBoxLazy;
    private Box.Native cryptoBoxNative;

    @BeforeAll
    public void before() {
        cryptoBoxLazy = lazySodium;
        cryptoBoxNative = lazySodium;
    }

    @Test
    public void generateKeyPair() throws SodiumException {
        KeyPair keys = cryptoBoxLazy.cryptoBoxKeypair();
        assertNotNull(keys);
    }

    @Test
    public void generateDeterministicKeyPair() throws SodiumException {
        byte[] seed = lazySodium.randomBytesBuf(Box.SEEDBYTES);
        KeyPair keys = cryptoBoxLazy.cryptoBoxSeedKeypair(seed);
        KeyPair keys2 = cryptoBoxLazy.cryptoBoxSeedKeypair(seed);

        assertEquals(keys.getPublicKey().getAsHexString(), keys2.getPublicKey().getAsHexString());
        assertEquals(keys.getSecretKey().getAsHexString(), keys2.getSecretKey().getAsHexString());
    }


    @Test
    public void encryptMessage() throws SodiumException {
        String message = "This should get encrypted";

        // Generate the client's keypair
        KeyPair clientKeys = cryptoBoxLazy.cryptoBoxKeypair();

        // Generate the server keypair
        KeyPair serverKeys = cryptoBoxLazy.cryptoBoxKeypair();


        // We're going to encrypt a message on the client and
        // send it to the server.
        byte[] nonce = lazySodium.nonce(Box.NONCEBYTES);
        KeyPair encryptionKeyPair = new KeyPair(serverKeys.getPublicKey(), clientKeys.getSecretKey());
        String encrypted = cryptoBoxLazy.cryptoBoxEasy(message, nonce, encryptionKeyPair);

        // ... In this space, you can theoretically send encrypted to
        // the server.

        // Now we can decrypt the encrypted message.
        KeyPair decryptionKeyPair = new KeyPair(clientKeys.getPublicKey(), serverKeys.getSecretKey());
        String decryptedMessage = cryptoBoxLazy.cryptoBoxOpenEasy(encrypted, nonce, decryptionKeyPair);

        // Public-private key encryption complete!
        assertEquals(message, decryptedMessage);
    }


    @Test
    public void encryptMessageBeforeNm() throws SodiumException {
        String message = "This should get encrypted";

        // Generate a keypair
        KeyPair keyPair = cryptoBoxLazy.cryptoBoxKeypair();

        // Generate a shared key which can be used
        // to encrypt and decrypt data
        String sharedKey = cryptoBoxLazy.cryptoBoxBeforeNm(keyPair);

        byte[] nonce = lazySodium.nonce(Box.NONCEBYTES);

        // Encrypt the data using the shared key
        String encrypted = cryptoBoxLazy.cryptoBoxEasyAfterNm(message, nonce, sharedKey);

        // Decrypt the data using the shared key
        String decryptedMessage = cryptoBoxLazy.cryptoBoxOpenEasyAfterNm(encrypted, nonce, sharedKey);

        assertEquals(message, decryptedMessage);
    }

    @Test
    public void encryptMessageBeforeNmDetached() throws SodiumException {
        String message = "This should get encrypted";

        // Generate a keypair
        KeyPair keyPair = cryptoBoxLazy.cryptoBoxKeypair();

        // Generate a shared key which can be used
        // to encrypt and decrypt data
        String sharedKey = cryptoBoxLazy.cryptoBoxBeforeNm(keyPair);

        byte[] nonce2 = lazySodium.nonce(Box.NONCEBYTES);

        // Use the detached functions
        DetachedEncrypt encDet = cryptoBoxLazy.cryptoBoxDetachedAfterNm(message, nonce2, sharedKey);
        DetachedDecrypt decryptDet = cryptoBoxLazy.cryptoBoxOpenDetachedAfterNm(encDet, nonce2, sharedKey);

        assertEquals(message, lazySodium.str(decryptDet.getMessage()));
    }

    @Test
    public void sealMessage() throws SodiumException {
        String message = "This should get encrypted";

        // Generate the keypair
        KeyPair keyPair = cryptoBoxLazy.cryptoBoxKeypair();

        // Encrypt the message
        String encrypted = cryptoBoxLazy.cryptoBoxSealEasy(message, keyPair.getPublicKey());

        // Now we can decrypt the encrypted message.
        String decryptedMessage = cryptoBoxLazy.cryptoBoxSealOpenEasy(encrypted, keyPair);

        // Public-private key encryption complete!
        assertEquals(message, decryptedMessage);
    }

    @Test
    public void cryptoBoxKeypairChecks() {
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxKeypair(new byte[Box.PUBLICKEYBYTES - 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxKeypair(new byte[Box.PUBLICKEYBYTES + 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxKeypair(publicKey, new byte[Box.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxKeypair(publicKey, new byte[Box.SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoBoxSeedKeypairChecks() {
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];
        byte[] seed = new byte[Box.SEEDBYTES];
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSeedKeypair(new byte[Box.PUBLICKEYBYTES - 1], secretKey, seed));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSeedKeypair(new byte[Box.PUBLICKEYBYTES + 1], secretKey, seed));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSeedKeypair(publicKey, new byte[Box.SECRETKEYBYTES - 1], seed));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSeedKeypair(publicKey, new byte[Box.SECRETKEYBYTES + 1], seed));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSeedKeypair(publicKey, secretKey, new byte[Box.SEEDBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSeedKeypair(publicKey, secretKey, new byte[Box.SEEDBYTES + 1]));
    }

    @Test
    public void cryptoBoxEasyChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length + Box.MACBYTES];
        byte[] nonce = new byte[Box.NONCEBYTES];
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasy(cipherText, message, -1, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasy(cipherText, message, message.length + 1, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasy(new byte[cipherText.length - 1], message, message.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasy(new byte[cipherText.length + 1], message, message.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasy(cipherText, message, message.length, new byte[Box.NONCEBYTES - 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasy(cipherText, message, message.length, new byte[Box.NONCEBYTES + 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasy(cipherText, message, message.length, nonce, new byte[Box.PUBLICKEYBYTES - 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasy(cipherText, message, message.length, nonce, new byte[Box.PUBLICKEYBYTES + 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasy(cipherText, message, message.length, nonce, publicKey, new byte[Box.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasy(cipherText, message, message.length, nonce, publicKey, new byte[Box.SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoBoxOpenEasyChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[100];
        byte[] nonce = new byte[Box.NONCEBYTES];
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasy(message, cipherText, -1, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasy(message, cipherText, cipherText.length + 1, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasy(new byte[message.length - 1], cipherText, cipherText.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasy(new byte[message.length + 1], cipherText, cipherText.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasy(message, cipherText, cipherText.length, new byte[Box.NONCEBYTES - 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasy(message, cipherText, cipherText.length, new byte[Box.NONCEBYTES + 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasy(message, cipherText, cipherText.length, nonce, new byte[Box.PUBLICKEYBYTES - 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasy(message, cipherText, cipherText.length, nonce, new byte[Box.PUBLICKEYBYTES + 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasy(message, cipherText, cipherText.length, nonce, publicKey, new byte[Box.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasy(message, cipherText, cipherText.length, nonce, publicKey, new byte[Box.SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoBoxDetachedChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length];
        byte[] mac = new byte[Box.MACBYTES];
        byte[] nonce = new byte[Box.NONCEBYTES];
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetached(new byte[message.length - 1], mac, message, message.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetached(new byte[message.length + 1], mac, message, message.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetached(cipherText, new byte[Box.MACBYTES - 1], message, message.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetached(cipherText, new byte[Box.MACBYTES + 1], message, message.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetached(cipherText, mac, message, -1, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetached(cipherText, mac, message, message.length + 1, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetached(cipherText, mac, message, message.length, new byte[Box.NONCEBYTES - 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetached(cipherText, mac, message, message.length, new byte[Box.NONCEBYTES + 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetached(cipherText, mac, message, message.length, nonce, new byte[Box.PUBLICKEYBYTES - 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetached(cipherText, mac, message, message.length, nonce, new byte[Box.PUBLICKEYBYTES + 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetached(cipherText, mac, message, message.length, nonce, publicKey, new byte[Box.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetached(cipherText, mac, message, message.length, nonce, publicKey, new byte[Box.SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoBoxOpenDetachedChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length];
        byte[] mac = new byte[Box.MACBYTES];
        byte[] nonce = new byte[Box.NONCEBYTES];
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetached(new byte[message.length - 1], cipherText, mac, cipherText.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetached(new byte[message.length + 1], cipherText, mac, cipherText.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetached(message, cipherText, new byte[Box.MACBYTES - 1], cipherText.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetached(message, cipherText, new byte[Box.MACBYTES + 1], cipherText.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetached(message, cipherText, mac, -1, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetached(message, cipherText, mac, cipherText.length + 1, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetached(message, cipherText, mac, cipherText.length, new byte[Box.NONCEBYTES - 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetached(message, cipherText, mac, cipherText.length, new byte[Box.NONCEBYTES + 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetached(message, cipherText, mac, cipherText.length, nonce, new byte[Box.PUBLICKEYBYTES - 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetached(message, cipherText, mac, cipherText.length, nonce, new byte[Box.PUBLICKEYBYTES + 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetached(message, cipherText, mac, cipherText.length, nonce, publicKey, new byte[Box.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetached(message, cipherText, mac, cipherText.length, nonce, publicKey, new byte[Box.SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoBoxBeforeNmChecks() {
        byte[] k = new byte[Box.BEFORENMBYTES];
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxBeforeNm(new byte[Box.BEFORENMBYTES - 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxBeforeNm(new byte[Box.BEFORENMBYTES + 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxBeforeNm(k, new byte[Box.PUBLICKEYBYTES - 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxBeforeNm(k, new byte[Box.PUBLICKEYBYTES + 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxBeforeNm(k, publicKey, new byte[Box.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxBeforeNm(k, publicKey, new byte[Box.SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoBoxEasyAfterNmChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length + Box.MACBYTES];
        byte[] nonce = new byte[Box.NONCEBYTES];
        byte[] k = new byte[Box.BEFORENMBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasyAfterNm(cipherText, message, -1, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasyAfterNm(cipherText, message, message.length + 1, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasyAfterNm(new byte[cipherText.length - 1], message, message.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasyAfterNm(new byte[cipherText.length + 1], message, message.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasyAfterNm(cipherText, message, message.length, new byte[Box.NONCEBYTES - 1], k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasyAfterNm(cipherText, message, message.length, new byte[Box.NONCEBYTES + 1], k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasyAfterNm(cipherText, message, message.length, nonce, new byte[Box.BEFORENMBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxEasyAfterNm(cipherText, message, message.length, nonce, new byte[Box.BEFORENMBYTES + 1]));
    }

    @Test
    public void cryptoBoxOpenEasyAfterNmChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length + Box.MACBYTES];
        byte[] nonce = new byte[Box.NONCEBYTES];
        byte[] k = new byte[Box.BEFORENMBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasyAfterNm(message, cipherText, -1, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasyAfterNm(message, cipherText, cipherText.length + 1, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasyAfterNm(new byte[message.length - 1], cipherText, cipherText.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasyAfterNm(new byte[message.length + 1], cipherText, cipherText.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasyAfterNm(message, cipherText, cipherText.length, new byte[Box.NONCEBYTES - 1], k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasyAfterNm(message, cipherText, cipherText.length, new byte[Box.NONCEBYTES + 1], k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasyAfterNm(message, cipherText, cipherText.length, nonce, new byte[Box.BEFORENMBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenEasyAfterNm(message, cipherText, cipherText.length, nonce, new byte[Box.BEFORENMBYTES + 1]));
    }

    @Test
    public void cryptoBoxDetachedAfterNmChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length];
        byte[] mac = new byte[Box.MACBYTES];
        byte[] nonce = new byte[Box.NONCEBYTES];
        byte[] k = new byte[Box.BEFORENMBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetachedAfterNm(new byte[message.length - 1], mac, message, message.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetachedAfterNm(new byte[message.length + 1], mac, message, message.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetachedAfterNm(cipherText, new byte[Box.MACBYTES - 1], message, message.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetachedAfterNm(cipherText, new byte[Box.MACBYTES + 1], message, message.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetachedAfterNm(cipherText, mac, message, -1, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetachedAfterNm(cipherText, mac, message, message.length + 1, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetachedAfterNm(cipherText, mac, message, message.length, new byte[Box.NONCEBYTES - 1], k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetachedAfterNm(cipherText, mac, message, message.length, new byte[Box.NONCEBYTES + 1], k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetachedAfterNm(cipherText, mac, message, message.length, nonce, new byte[Box.BEFORENMBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxDetachedAfterNm(cipherText, mac, message, message.length, nonce, new byte[Box.BEFORENMBYTES + 1]));
    }

    @Test
    public void cryptoBoxOpenDetachedAfterNmChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length];
        byte[] mac = new byte[Box.MACBYTES];
        byte[] nonce = new byte[Box.NONCEBYTES];
        byte[] k = new byte[Box.BEFORENMBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetachedAfterNm(new byte[message.length - 1], cipherText, mac, cipherText.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetachedAfterNm(new byte[message.length + 1], cipherText, mac, cipherText.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetachedAfterNm(message, cipherText, new byte[Box.MACBYTES - 1], cipherText.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetachedAfterNm(message, cipherText, new byte[Box.MACBYTES + 1], cipherText.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetachedAfterNm(message, cipherText, mac, -1, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetachedAfterNm(message, cipherText, mac, cipherText.length + 1, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetachedAfterNm(message, cipherText, mac, cipherText.length, new byte[Box.NONCEBYTES - 1], k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetachedAfterNm(message, cipherText, mac, cipherText.length, new byte[Box.NONCEBYTES + 1], k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetachedAfterNm(message, cipherText, mac, cipherText.length, nonce, new byte[Box.BEFORENMBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxOpenDetachedAfterNm(message, cipherText, mac, cipherText.length, nonce, new byte[Box.BEFORENMBYTES + 1]));
    }

    @Test
    public void cryptoBoxSealChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length + Box.SEALBYTES];
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSeal(cipherText, message, -1, publicKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSeal(cipherText, message, message.length + 1, publicKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSeal(new byte[cipherText.length - 1], message, message.length, publicKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSeal(new byte[cipherText.length + 1], message, message.length, publicKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSeal(cipherText, message, message.length, new byte[Box.PUBLICKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSeal(cipherText, message, message.length, new byte[Box.PUBLICKEYBYTES + 1]));
    }

    @Test
    public void cryptoBoxSealOpenChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length + Box.SEALBYTES];
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSealOpen(message, cipherText, -1, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSealOpen(message, cipherText, cipherText.length + 1, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSealOpen(new byte[message.length - 1], cipherText, cipherText.length, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSealOpen(new byte[message.length + 1], cipherText, cipherText.length, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSealOpen(message, cipherText, cipherText.length, new byte[Box.PUBLICKEYBYTES - 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSealOpen(message, cipherText, cipherText.length, new byte[Box.PUBLICKEYBYTES + 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSealOpen(message, cipherText, cipherText.length, publicKey, new byte[Box.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxSealOpen(message, cipherText, cipherText.length, publicKey, new byte[Box.SECRETKEYBYTES + 1]));
    }

    // -- XChaCha20Poly1305

    @Test
    public void cryptoBoxCurve25519XChaCha20Poly1305Keypair() {
        byte[] publicKey = new byte[Box.CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Keypair(publicKey, secretKey));
    }

    @Test
    public void cryptoBoxCurve25519XChaCha20Poly1305SeedKeypair() {
        byte[] seed = lazySodium.randomBytesBuf(Box.CURVE25519XCHACHA20POLY1305_SEEDBYTES);
        byte[] publicKey1 = new byte[Box.CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES];
        byte[] secretKey1 = new byte[Box.CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES];
        byte[] publicKey2 = new byte[Box.CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES];
        byte[] secretKey2 = new byte[Box.CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SeedKeypair(publicKey1, secretKey1, seed));
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SeedKeypair(publicKey2, secretKey2, seed));

        assertArrayEquals(publicKey1, publicKey2);
        assertArrayEquals(secretKey1, secretKey2);
    }

    @Test
    public void encryptMessageCurve25519XChaCha20Poly1305() {
        String message = "This should get encrypted";

        byte[] publicKeyServer = new byte[Box.CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES];
        byte[] secretKeyServer = new byte[Box.CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES];
        byte[] publicKeyClient = new byte[Box.CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES];
        byte[] secretKeyClient = new byte[Box.CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Keypair(publicKeyServer, secretKeyServer));
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Keypair(publicKeyClient, secretKeyClient));

        // We're going to encrypt a message on the client and
        // send it to the server.
        byte[] nonce = lazySodium.nonce(Box.CURVE25519XCHACHA20POLY1305_NONCEBYTES);
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] cipherText = new byte[messageBytes.length + Box.CURVE25519XCHACHA20POLY1305_MACBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Easy(cipherText, messageBytes, messageBytes.length, nonce, publicKeyServer, secretKeyClient));

        // ... In this space, you can theoretically send encrypted to
        // the server.

        // Now we can decrypt the encrypted message.
        byte[] decryptedBytes = new byte[cipherText.length - Box.CURVE25519XCHACHA20POLY1305_MACBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasy(decryptedBytes, cipherText, cipherText.length, nonce, publicKeyClient, secretKeyServer));
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

        // Public-private key encryption complete!
        assertEquals(message, decryptedMessage);
    }

    @Test
    public void cannotDecryptChaChaWithSalsa() {
        String message = "This should get encrypted";

        byte[] publicKeyServer = new byte[Box.CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES];
        byte[] secretKeyServer = new byte[Box.CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES];
        byte[] publicKeyClient = new byte[Box.CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES];
        byte[] secretKeyClient = new byte[Box.CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Keypair(publicKeyServer, secretKeyServer));
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Keypair(publicKeyClient, secretKeyClient));

        byte[] nonce = lazySodium.nonce(Box.CURVE25519XCHACHA20POLY1305_NONCEBYTES);
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] cipherText = new byte[messageBytes.length + Box.CURVE25519XCHACHA20POLY1305_MACBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Easy(cipherText, messageBytes, messageBytes.length, nonce, publicKeyServer, secretKeyClient));

        byte[] decryptedBytes = new byte[cipherText.length - Box.MACBYTES];
        assertFalse(cryptoBoxNative.cryptoBoxOpenEasy(decryptedBytes, cipherText, cipherText.length, nonce, publicKeyClient, secretKeyServer));
    }

    @Test
    public void encryptMessageBeforeNmCurve25519XChaCha20Poly1305() {
        String message = "This should get encrypted";

        // Generate a keypair
        byte[] publicKey = new byte[Box.CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Keypair(publicKey, secretKey));

        // Generate a shared key which can be used
        // to encrypt and decrypt data
        byte[] sharedKey = new byte[Box.CURVE25519XCHACHA20POLY1305_BEFORENMBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305BeforeNm(sharedKey, publicKey, secretKey));

        // Encrypt the data using the shared key
        byte[] nonce = lazySodium.nonce(Box.CURVE25519XCHACHA20POLY1305_NONCEBYTES);
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = new byte[messageBytes.length + Box.CURVE25519XCHACHA20POLY1305_MACBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305EasyAfterNm(encrypted, messageBytes, messageBytes.length, nonce, sharedKey));

        // Decrypt the data using the shared key
        byte[] decryptedBytes = new byte[encrypted.length - Box.CURVE25519XCHACHA20POLY1305_MACBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasyAfterNm(decryptedBytes, encrypted, encrypted.length, nonce, sharedKey));
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

        assertEquals(message, decryptedMessage);
    }

    @Test
    public void encryptMessageBeforeNmDetachedCurve25519XChaCha20Poly1305() {
        String message = "This should get encrypted";

        // Generate a keypair
        byte[] publicKey = new byte[Box.CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Keypair(publicKey, secretKey));

        // Generate a shared key which can be used
        // to encrypt and decrypt data
        byte[] sharedKey = new byte[Box.CURVE25519XCHACHA20POLY1305_BEFORENMBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305BeforeNm(sharedKey, publicKey, secretKey));

        // Encrypt the data using the shared key
        byte[] nonce = lazySodium.nonce(Box.CURVE25519XCHACHA20POLY1305_NONCEBYTES);
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = new byte[messageBytes.length];
        byte[] mac = new byte[Box.CURVE25519XCHACHA20POLY1305_MACBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305DetachedAfterNm(encrypted, mac, messageBytes, messageBytes.length, nonce, sharedKey));

        // Decrypt the data using the shared key
        byte[] decryptedBytes = new byte[encrypted.length];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetachedAfterNm(decryptedBytes, encrypted, mac, encrypted.length, nonce, sharedKey));
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

        assertEquals(message, decryptedMessage);

        // fail after changing a single bit of the MAC
        mac[mac.length / 2] ^= 0x40;
        assertFalse(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetachedAfterNm(decryptedBytes, encrypted, mac, encrypted.length, nonce, sharedKey));
    }

    @Test
    public void sealMessageCurve25519XChaCha20Poly1305() {
        String message = "This should get encrypted";

        // Generate a keypair
        byte[] publicKey = new byte[Box.CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Keypair(publicKey, secretKey));

        // Encrypt the message
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] cipherBytes = new byte[messageBytes.length + Box.CURVE25519XCHACHA20POLY1305_SEALBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Seal(cipherBytes, messageBytes, messageBytes.length, publicKey));

        // Now we can decrypt the encrypted message.
        byte[] decrypted = new byte[cipherBytes.length - Box.CURVE25519XCHACHA20POLY1305_SEALBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SealOpen(decrypted, cipherBytes, cipherBytes.length, publicKey, secretKey));
        String decryptedMessage = new String(decrypted, StandardCharsets.UTF_8);

        // Public-private key encryption complete!
        assertEquals(message, decryptedMessage);
    }

    @Test
    public void cannotOpenChachaSealWithSalsa() {
        String message = "This should get encrypted";

        // Generate a keypair
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxKeypair(publicKey, secretKey));

        // Encrypt the message
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] cipherBytes = new byte[messageBytes.length + Box.SEALBYTES];
        assertTrue(cryptoBoxNative.cryptoBoxSeal(cipherBytes, messageBytes, messageBytes.length, publicKey));

        // Now try to decrypt the encrypted message
        byte[] decrypted = new byte[cipherBytes.length - Box.CURVE25519XCHACHA20POLY1305_SEALBYTES];
        assertFalse(cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SealOpen(decrypted, cipherBytes, cipherBytes.length, publicKey, secretKey));
    }

    @Test
    public void cryptoBoxCurve25519XChaCha20Poly1305KeypairChecks() {
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Keypair(new byte[Box.PUBLICKEYBYTES - 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Keypair(new byte[Box.PUBLICKEYBYTES + 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Keypair(publicKey, new byte[Box.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Keypair(publicKey, new byte[Box.SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoBoxCurve25519XChaCha20Poly1305SeedKeypairChecks() {
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];
        byte[] seed = new byte[Box.SEEDBYTES];
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SeedKeypair(new byte[Box.PUBLICKEYBYTES - 1], secretKey, seed));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SeedKeypair(new byte[Box.PUBLICKEYBYTES + 1], secretKey, seed));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SeedKeypair(publicKey, new byte[Box.SECRETKEYBYTES - 1], seed));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SeedKeypair(publicKey, new byte[Box.SECRETKEYBYTES + 1], seed));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SeedKeypair(publicKey, secretKey, new byte[Box.SEEDBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SeedKeypair(publicKey, secretKey, new byte[Box.SEEDBYTES + 1]));
    }

    @Test
    public void cryptoBoxCurve25519XChaCha20Poly1305EasyChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length + Box.MACBYTES];
        byte[] nonce = new byte[Box.NONCEBYTES];
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Easy(cipherText, message, -1, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Easy(cipherText, message, message.length + 1, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Easy(new byte[cipherText.length - 1], message, message.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Easy(new byte[cipherText.length + 1], message, message.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Easy(cipherText, message, message.length, new byte[Box.NONCEBYTES - 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Easy(cipherText, message, message.length, new byte[Box.NONCEBYTES + 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Easy(cipherText, message, message.length, nonce, new byte[Box.PUBLICKEYBYTES - 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Easy(cipherText, message, message.length, nonce, new byte[Box.PUBLICKEYBYTES + 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Easy(cipherText, message, message.length, nonce, publicKey, new byte[Box.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Easy(cipherText, message, message.length, nonce, publicKey, new byte[Box.SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoBoxCurve25519XChaCha20Poly1305OpenEasyChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[100];
        byte[] nonce = new byte[Box.NONCEBYTES];
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasy(message, cipherText, -1, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasy(message, cipherText, cipherText.length + 1, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasy(new byte[message.length - 1], cipherText, cipherText.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasy(new byte[message.length + 1], cipherText, cipherText.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasy(message, cipherText, cipherText.length, new byte[Box.NONCEBYTES - 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasy(message, cipherText, cipherText.length, new byte[Box.NONCEBYTES + 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasy(message, cipherText, cipherText.length, nonce, new byte[Box.PUBLICKEYBYTES - 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasy(message, cipherText, cipherText.length, nonce, new byte[Box.PUBLICKEYBYTES + 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasy(message, cipherText, cipherText.length, nonce, publicKey, new byte[Box.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasy(message, cipherText, cipherText.length, nonce, publicKey, new byte[Box.SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoBoxCurve25519XChaCha20Poly1305DetachedChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length];
        byte[] mac = new byte[Box.MACBYTES];
        byte[] nonce = new byte[Box.NONCEBYTES];
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Detached(new byte[message.length - 1], mac, message, message.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Detached(new byte[message.length + 1], mac, message, message.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Detached(cipherText, new byte[Box.MACBYTES - 1], message, message.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Detached(cipherText, new byte[Box.MACBYTES + 1], message, message.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Detached(cipherText, mac, message, -1, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Detached(cipherText, mac, message, message.length + 1, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Detached(cipherText, mac, message, message.length, new byte[Box.NONCEBYTES - 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Detached(cipherText, mac, message, message.length, new byte[Box.NONCEBYTES + 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Detached(cipherText, mac, message, message.length, nonce, new byte[Box.PUBLICKEYBYTES - 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Detached(cipherText, mac, message, message.length, nonce, new byte[Box.PUBLICKEYBYTES + 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Detached(cipherText, mac, message, message.length, nonce, publicKey, new byte[Box.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Detached(cipherText, mac, message, message.length, nonce, publicKey, new byte[Box.SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoBoxCurve25519XChaCha20Poly1305OpenDetachedChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length];
        byte[] mac = new byte[Box.MACBYTES];
        byte[] nonce = new byte[Box.NONCEBYTES];
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetached(new byte[message.length - 1], cipherText, mac, cipherText.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetached(new byte[message.length + 1], cipherText, mac, cipherText.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetached(message, cipherText, new byte[Box.MACBYTES - 1], cipherText.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetached(message, cipherText, new byte[Box.MACBYTES + 1], cipherText.length, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetached(message, cipherText, mac, -1, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetached(message, cipherText, mac, cipherText.length + 1, nonce, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetached(message, cipherText, mac, cipherText.length, new byte[Box.NONCEBYTES - 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetached(message, cipherText, mac, cipherText.length, new byte[Box.NONCEBYTES + 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetached(message, cipherText, mac, cipherText.length, nonce, new byte[Box.PUBLICKEYBYTES - 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetached(message, cipherText, mac, cipherText.length, nonce, new byte[Box.PUBLICKEYBYTES + 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetached(message, cipherText, mac, cipherText.length, nonce, publicKey, new byte[Box.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetached(message, cipherText, mac, cipherText.length, nonce, publicKey, new byte[Box.SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoBoxCurve25519XChaCha20Poly1305BeforeNmChecks() {
        byte[] k = new byte[Box.BEFORENMBYTES];
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305BeforeNm(new byte[Box.BEFORENMBYTES - 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305BeforeNm(new byte[Box.BEFORENMBYTES + 1], publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305BeforeNm(k, new byte[Box.PUBLICKEYBYTES - 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305BeforeNm(k, new byte[Box.PUBLICKEYBYTES + 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305BeforeNm(k, publicKey, new byte[Box.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305BeforeNm(k, publicKey, new byte[Box.SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoBoxCurve25519XChaCha20Poly1305EasyAfterNmChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length + Box.MACBYTES];
        byte[] nonce = new byte[Box.NONCEBYTES];
        byte[] k = new byte[Box.BEFORENMBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305EasyAfterNm(cipherText, message, -1, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305EasyAfterNm(cipherText, message, message.length + 1, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305EasyAfterNm(new byte[cipherText.length - 1], message, message.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305EasyAfterNm(new byte[cipherText.length + 1], message, message.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305EasyAfterNm(cipherText, message, message.length, new byte[Box.NONCEBYTES - 1], k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305EasyAfterNm(cipherText, message, message.length, new byte[Box.NONCEBYTES + 1], k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305EasyAfterNm(cipherText, message, message.length, nonce, new byte[Box.BEFORENMBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305EasyAfterNm(cipherText, message, message.length, nonce, new byte[Box.BEFORENMBYTES + 1]));
    }

    @Test
    public void cryptoBoxCurve25519XChaCha20Poly1305OpenEasyAfterNmChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length + Box.MACBYTES];
        byte[] nonce = new byte[Box.NONCEBYTES];
        byte[] k = new byte[Box.BEFORENMBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasyAfterNm(message, cipherText, -1, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasyAfterNm(message, cipherText, cipherText.length + 1, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasyAfterNm(new byte[message.length - 1], cipherText, cipherText.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasyAfterNm(new byte[message.length + 1], cipherText, cipherText.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasyAfterNm(message, cipherText, cipherText.length, new byte[Box.NONCEBYTES - 1], k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasyAfterNm(message, cipherText, cipherText.length, new byte[Box.NONCEBYTES + 1], k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasyAfterNm(message, cipherText, cipherText.length, nonce, new byte[Box.BEFORENMBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenEasyAfterNm(message, cipherText, cipherText.length, nonce, new byte[Box.BEFORENMBYTES + 1]));
    }

    @Test
    public void cryptoBoxCurve25519XChaCha20Poly1305DetachedAfterNmChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length];
        byte[] mac = new byte[Box.MACBYTES];
        byte[] nonce = new byte[Box.NONCEBYTES];
        byte[] k = new byte[Box.BEFORENMBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305DetachedAfterNm(new byte[message.length - 1], mac, message, message.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305DetachedAfterNm(new byte[message.length + 1], mac, message, message.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305DetachedAfterNm(cipherText, new byte[Box.MACBYTES - 1], message, message.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305DetachedAfterNm(cipherText, new byte[Box.MACBYTES + 1], message, message.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305DetachedAfterNm(cipherText, mac, message, -1, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305DetachedAfterNm(cipherText, mac, message, message.length + 1, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305DetachedAfterNm(cipherText, mac, message, message.length, new byte[Box.NONCEBYTES - 1], k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305DetachedAfterNm(cipherText, mac, message, message.length, new byte[Box.NONCEBYTES + 1], k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305DetachedAfterNm(cipherText, mac, message, message.length, nonce, new byte[Box.BEFORENMBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305DetachedAfterNm(cipherText, mac, message, message.length, nonce, new byte[Box.BEFORENMBYTES + 1]));
    }

    @Test
    public void cryptoBoxCurve25519XChaCha20Poly1305OpenDetachedAfterNmChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length];
        byte[] mac = new byte[Box.MACBYTES];
        byte[] nonce = new byte[Box.NONCEBYTES];
        byte[] k = new byte[Box.BEFORENMBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetachedAfterNm(new byte[message.length - 1], cipherText, mac, cipherText.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetachedAfterNm(new byte[message.length + 1], cipherText, mac, cipherText.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetachedAfterNm(message, cipherText, new byte[Box.MACBYTES - 1], cipherText.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetachedAfterNm(message, cipherText, new byte[Box.MACBYTES + 1], cipherText.length, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetachedAfterNm(message, cipherText, mac, -1, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetachedAfterNm(message, cipherText, mac, cipherText.length + 1, nonce, k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetachedAfterNm(message, cipherText, mac, cipherText.length, new byte[Box.NONCEBYTES - 1], k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetachedAfterNm(message, cipherText, mac, cipherText.length, new byte[Box.NONCEBYTES + 1], k));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetachedAfterNm(message, cipherText, mac, cipherText.length, nonce, new byte[Box.BEFORENMBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305OpenDetachedAfterNm(message, cipherText, mac, cipherText.length, nonce, new byte[Box.BEFORENMBYTES + 1]));
    }

    @Test
    public void cryptoBoxCurve25519XChaCha20Poly1305SealChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length + Box.SEALBYTES];
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Seal(cipherText, message, -1, publicKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Seal(cipherText, message, message.length + 1, publicKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Seal(new byte[cipherText.length - 1], message, message.length, publicKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Seal(new byte[cipherText.length + 1], message, message.length, publicKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Seal(cipherText, message, message.length, new byte[Box.PUBLICKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305Seal(cipherText, message, message.length, new byte[Box.PUBLICKEYBYTES + 1]));
    }

    @Test
    public void cryptoBoxCurve25519XChaCha20Poly1305SealOpenChecks() {
        byte[] message = new byte[100];
        byte[] cipherText = new byte[message.length + Box.SEALBYTES];
        byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Box.SECRETKEYBYTES];

        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SealOpen(message, cipherText, -1, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SealOpen(message, cipherText, cipherText.length + 1, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SealOpen(new byte[message.length - 1], cipherText, cipherText.length, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SealOpen(new byte[message.length + 1], cipherText, cipherText.length, publicKey, secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SealOpen(message, cipherText, cipherText.length, new byte[Box.PUBLICKEYBYTES - 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SealOpen(message, cipherText, cipherText.length, new byte[Box.PUBLICKEYBYTES + 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SealOpen(message, cipherText, cipherText.length, publicKey, new byte[Box.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoBoxNative.cryptoBoxCurve25519XChaCha20Poly1305SealOpen(message, cipherText, cipherText.length, publicKey, new byte[Box.SECRETKEYBYTES + 1]));
    }

    
    
    
    
}
