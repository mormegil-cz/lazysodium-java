/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.interfaces;


import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.utils.BaseChecker;
import com.goterl.lazysodium.utils.DetachedEncrypt;
import com.goterl.lazysodium.utils.Key;

public interface SecretBox {


    int XSALSA20POLY1305_KEYBYTES = 32,
        XSALSA20POLY1305_NONCEBYTES = 24,
        XSALSA20POLY1305_MACBYTES = 16;

    int KEYBYTES = XSALSA20POLY1305_KEYBYTES,
        MACBYTES = XSALSA20POLY1305_MACBYTES,
        NONCEBYTES = XSALSA20POLY1305_NONCEBYTES;


    class Checker extends BaseChecker {

        public static void checkKey(byte[] key) {
            checkEqual("key length", key.length, KEYBYTES);
        }

        public static void checkNonce(byte[] nonce) {
            checkEqual("nonce length", nonce.length, NONCEBYTES);
        }

        public static void checkCipherTextLength(long cipherTextLen) {
            checkAtLeast("cipher text length", cipherTextLen, MACBYTES);
        }

    }


    interface Native {

        /**
         * Creates a random key. It is equivalent to calling
         * {@link Random#randomBytesBuf(int)} but improves code
         * clarity and can prevent misuse by ensuring
         * that the provided key length is
         * always correct.
         * @param key The key which is of size {@link #KEYBYTES}.
         */
        void cryptoSecretBoxKeygen(byte[] key);

        /**
         * Encrypts a message using a key generated by {@link #cryptoSecretBoxKeygen(byte[])}.
         * @param cipherText The cipher text. Should be at least {@link #MACBYTES} + {@code messageLen}.
         * @param message The message to encrypt.
         * @param messageLen The message byte array length.
         * @param nonce A nonce of size {@link #NONCEBYTES} generated by {@link Random#randomBytesBuf(int)}.
         * @param key The symmetric key generated by {@link #cryptoSecretBoxKeygen(byte[])}.
         * @return True if successful.
         */
        boolean cryptoSecretBoxEasy(byte[] cipherText,
                                 byte[] message,
                                 int messageLen,
                                 byte[] nonce,
                                 byte[] key);

        /**
         * Decrypts and verifies a message using a key generated
         * by {@link #cryptoSecretBoxKeygen(byte[])}.
         * @param message The message will be put into here once decrypted.
         * @param cipherText The cipher produced by {@link #cryptoSecretBoxEasy(byte[], byte[], int, byte[], byte[])}.
         * @param cipherTextLen The cipher text length.
         * @param nonce This has to be the same nonce that was used when
         *              encrypting using {@code cryptoSecretBoxEasy}.
         * @param key The key generated by {@link #cryptoSecretBoxKeygen(byte[])}.
         * @return True if successful.
         */
        boolean cryptoSecretBoxOpenEasy(byte[] message,
                                      byte[] cipherText,
                                      int cipherTextLen,
                                      byte[] nonce,
                                      byte[] key);

        /**
         * Encrypts a message. Alongside the cipher a mac is
         * returned which can be stored in separate locations.
         * @param cipherText The encrypted message of length {@code messageLen}.
         * @param mac The mac.
         * @param message The message to encrypt.
         * @param messageLen The message's length.
         * @param nonce A randomly generated nonce of size {@link #NONCEBYTES}. Use {@link Random#randomBytesBuf(int)}.
         * @param key The key generated by {@link #cryptoSecretBoxKeygen(byte[])}.
         * @return True if successful.
         */
        boolean cryptoSecretBoxDetached(byte[] cipherText,
                                     byte[] mac,
                                     byte[] message,
                                     int messageLen,
                                     byte[] nonce,
                                     byte[] key);

        /**
         * Decrypts a message with the mac and the cipher provided
         * separately.
         * @param message The message length which is the same size as {@code cipherTextLen}.
         * @param cipherText The cipher.
         * @param mac The mac.
         * @param cipherTextLen The cipher text length.
         * @param nonce The nonce that was used in {@link #cryptoSecretBoxDetached}.
         * @param key The key generated by {@link #cryptoSecretBoxKeygen(byte[])}.
         * @return True if successful.
         */
        boolean cryptoSecretBoxOpenDetached(byte[] message,
                                          byte[] cipherText,
                                          byte[] mac,
                                          int cipherTextLen,
                                          byte[] nonce,
                                          byte[] key);

    }

    interface Lazy {

        /**
         * Generates a secret symmetric key.
         * @return A secret symmetric key which has been through {@link Helpers.Lazy#sodiumBin2Hex(byte[])}.
         *
         */
        Key cryptoSecretBoxKeygen();


        /**
         * Encrypts a message.
         * @param message The message to encrypt.
         * @param nonce A randomly generated nonce of size {@link #NONCEBYTES}. Use {@link Random#randomBytesBuf(int)}.
         * @param key The key. A hexadecimal string that's been through {@link Helpers.Lazy#sodiumBin2Hex(byte[])}.
         * @return The cipher byte array that's been {@link Helpers.Lazy#sodiumBin2Hex(byte[])}'ified.
         */
        String cryptoSecretBoxEasy(String message, byte[] nonce, Key key) throws SodiumException;

        /**
         * Decrypts a message.
         * @param cipher The hexadecimal cipher text. See {@link Helpers.Lazy#sodiumBin2Hex(byte[])}.
         * @param nonce The nonce that was used when you encrypted with {@link #cryptoSecretBoxEasy(String, byte[], Key)}.
         * @param key The key. A hexadecimal string that's been through {@link Helpers.Lazy#sodiumBin2Hex(byte[])}.
         * @return The decrypted message.
         */
        String cryptoSecretBoxOpenEasy(String cipher, byte[] nonce, Key key) throws SodiumException;


        /**
         * Encrypts a message with the mac separately
         * @param message The message to encrypt.
         * @param nonce A randomly generated nonce of size {@link #NONCEBYTES}. Use {@link Random#randomBytesBuf(int)}.
         * @param key The key. A hexadecimal string that's been through {@link Helpers.Lazy#sodiumBin2Hex(byte[])}.
         * @return The cipher byte array that's been {@link Helpers.Lazy#sodiumBin2Hex(byte[])}'ified.
         */
        DetachedEncrypt cryptoSecretBoxDetached(String message, byte[] nonce, Key key) throws SodiumException;

        /**
         * Decrypts a message.
         * @param cipherAndMac The hexadecimal cipher text. See {@link Helpers.Lazy#sodiumBin2Hex(byte[])}.
         * @param nonce The nonce that was used when you encrypted with {@link #cryptoSecretBoxEasy(String, byte[], Key)}.
         * @param key The key. A hexadecimal string that's been through {@link Helpers.Lazy#sodiumBin2Hex(byte[])}.
         * @return The decrypted message.
         */
        String cryptoSecretBoxOpenDetached(DetachedEncrypt cipherAndMac, byte[] nonce, Key key) throws SodiumException;

    }


}
