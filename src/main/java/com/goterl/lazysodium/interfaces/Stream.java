/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.interfaces;


import com.goterl.lazysodium.utils.BaseChecker;
import com.goterl.lazysodium.utils.Constants;
import com.goterl.lazysodium.utils.Key;

public interface Stream {

    // REGULAR CHACHA

    int CHACHA20_NONCEBYTES = 8,
        CHACHA20_KEYBYTES = 32;
    long CHACHA20_MESSAGEBYTES_MAX = Constants.SIZE_MAX;


    // IETF CHACHA

    int CHACHA20_IETF_NONCEBYTES = 12,
        CHACHA20_IETF_KEYBYTES = 32;
    long CHACHA20_IETF_MESSAGEBYTES_MAX = Constants.GB_256;


    // SALSA20

    int SALSA20_NONCEBYTES = 12,
        SALSA20_KEYBYTES = 32;
    long SALSA20_MESSAGEBYTES_MAX = Constants.SIZE_MAX;


    // XSALSA20

    int XSALSA20_NONCEBYTES = 24,
        XSALSA20_KEYBYTES = 32;
    long XSALSA20_MESSAGEBYTES_MAX = Constants.SIZE_MAX;

    int NONCEBYTES = XSALSA20_NONCEBYTES,
        KEYBYTES = XSALSA20_KEYBYTES;
    long MESSAGEBYTES_MAX = XSALSA20_MESSAGEBYTES_MAX;


    enum Method {
        CHACHA20,
        CHACHA20_IETF,
        SALSA20,
        XSALSA20;

        @Deprecated
        public static final Method DEFAULT = XSALSA20;
    }


    interface Native {

        void cryptoStreamChaCha20Keygen(byte[] key);

        boolean cryptoStreamChaCha20(
                byte[] c,
                int cLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoStreamChaCha20Xor(
                byte[] cipher,
                byte[] message,
                int messageLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoStreamChaCha20XorIc(
                byte[] cipher,
                byte[] message,
                int messageLen,
                byte[] nonce,
                long ic,
                byte[] key
        );

        /**
         * Backward-compatible method name.
         * @deprecated Use {@link #cryptoStreamChaCha20XorIc(byte[], byte[], int, byte[], long, byte[])} instead.
         */
        @Deprecated(forRemoval = true)
        boolean cryptoStreamChacha20XorIc(
                byte[] cipher,
                byte[] message,
                int messageLen,
                byte[] nonce,
                long ic,
                byte[] key
        );

        // IETF CHACHA

        void cryptoStreamChaCha20IetfKeygen(byte[] key);

        boolean cryptoStreamChaCha20Ietf(
                byte[] c,
                int cLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoStreamChaCha20IetfXor(
                byte[] cipher,
                byte[] message,
                int messageLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoStreamChaCha20IetfXorIc(
                byte[] cipher,
                byte[] message,
                int messageLen,
                byte[] nonce,
                long ic,
                byte[] key
        );

        /**
         * Backward-compatible method name.
         * @deprecated Use {@link #cryptoStreamChaCha20XorIc(byte[], byte[], int, byte[], long, byte[])} instead.
         */
        @Deprecated(forRemoval = true)
        boolean cryptoStreamChacha20IetfXorIc(
                byte[] cipher,
                byte[] message,
                int messageLen,
                byte[] nonce,
                long ic,
                byte[] key
        );

        // Salsa20

        void cryptoStreamSalsa20Keygen(byte[] key);

        boolean cryptoStreamSalsa20(
                byte[] c,
                int cLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoStreamSalsa20Xor(
                byte[] cipher,
                byte[] message,
                int messageLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoStreamSalsa20XorIc(
                byte[] cipher,
                byte[] message,
                int messageLen,
                byte[] nonce,
                long ic,
                byte[] key
        );

        // XSalsa20

        void cryptoStreamXSalsa20Keygen(byte[] key);

        boolean cryptoStreamXSalsa20(
                byte[] c,
                int cLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoStreamXSalsa20Xor(
                byte[] cipher,
                byte[] message,
                int messageLen,
                byte[] nonce,
                byte[] key
        );

        boolean cryptoStreamXSalsa20XorIc(
                byte[] cipher,
                byte[] message,
                int messageLen,
                byte[] nonce,
                long ic,
                byte[] key
        );

    }



    interface Lazy {

        Key cryptoStreamKeygen(Method method);

        /**
         * Generate 20 bytes of keystream
         * @param nonce  Nonce
         * @param key    Key
         * @param method Stream cipher to use
         * @return 20-byte keystream data
         * @deprecated Use {@link #cryptoStream(int, byte[], Key, Method)} instead.
         */
        @Deprecated(forRemoval = true)
        byte[] cryptoStream(
                byte[] nonce,
                Key key,
                Method method
        );

        byte[] cryptoStream(
                int bytes,
                byte[] nonce,
                Key key,
                Method method
        );

        String cryptoStreamXor(
                String message,
                byte[] nonce,
                Key key,
                Method method
        );

        String cryptoStreamXorDecrypt(
                String cipher,
                byte[] nonce,
                Key key,
                Method method
        );

        String cryptoStreamXorIc(
                String message,
                byte[] nonce,
                long ic,
                Key key,
                Method method
        );

        String cryptoStreamXorIcDecrypt(
                String cipher,
                byte[] nonce,
                long ic,
                Key key,
                Method method
        );

    }


    final class Checker extends BaseChecker {
        private Checker() {}

        public static void checkChaCha20Key(byte[] key) {
            checkExpectedMemorySize("key length", key.length, CHACHA20_KEYBYTES);
        }

        public static void checkChaCha20Nonce(byte[] nonce) {
            checkExpectedMemorySize("nonce length", nonce.length, CHACHA20_NONCEBYTES);
        }

        public static void checkChaCha20IetfKey(byte[] key) {
            checkExpectedMemorySize("key length", key.length, CHACHA20_IETF_KEYBYTES);
        }

        public static void checkChaCha20IetfNonce(byte[] nonce) {
            checkExpectedMemorySize("nonce length", nonce.length, CHACHA20_IETF_NONCEBYTES);
        }

        public static void checkSalsa20Key(byte[] key) {
            checkExpectedMemorySize("key length", key.length, SALSA20_KEYBYTES);
        }

        public static void checkSalsa20Nonce(byte[] nonce) {
            checkExpectedMemorySize("nonce length", nonce.length, SALSA20_NONCEBYTES);
        }

        public static void checkXSalsa20Key(byte[] key) {
            checkExpectedMemorySize("key length", key.length, XSALSA20_KEYBYTES);
        }

        public static void checkXSalsa20Nonce(byte[] nonce) {
            checkExpectedMemorySize("nonce length", nonce.length, XSALSA20_NONCEBYTES);
        }

    }

}
