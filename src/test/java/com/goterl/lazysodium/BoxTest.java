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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

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

}
