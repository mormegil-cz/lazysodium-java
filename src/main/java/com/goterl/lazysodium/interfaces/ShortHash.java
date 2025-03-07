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
import com.goterl.lazysodium.utils.Key;
import com.sun.jna.NativeLong;

public interface ShortHash {

    int SIPHASH24_BYTES = 8,
        SIPHASH24_KEYBYTES = 16,
        SIPHASHX24_BYTES = 16,
        SIPHASHX24_KEYBYTES = 16,

        BYTES = SIPHASH24_BYTES,
        KEYBYTES = SIPHASH24_KEYBYTES;


    class Checker extends BaseChecker {
        public static void checkHash(byte[] hash) {
            checkEqual("hash length", hash.length, BYTES);
        }

        public static void checkKey(byte[] key) {
            checkEqual("key length", key.length, KEYBYTES);
        }
    }


    interface Native {

        /**
         * Short-input hash some text.
         * @param out The hashed text of size {@link #SIPHASH24_BYTES} or
         *            {@link #SIPHASHX24_BYTES} depending on {@code in} size.
         * @param in The short-input text to hash of size {@link #BYTES} or of size {@link #SIPHASHX24_BYTES}.
         * @param inLen The length of the short-input.
         * @param key The key generated via {@link #cryptoShortHashKeygen(byte[])}.
         * @return true if success, false if fail.
         */
        boolean cryptoShortHash(byte[] out, byte[] in, int inLen, byte[] key);


        /**
         * Output a 64-bit key.
         * @param k The key of size {@link #SIPHASH24_KEYBYTES}.
         */
        void cryptoShortHashKeygen(byte[] k);

    }

    interface Lazy {

        /**
         * Generate a 64-bit key for short-input hashing.
         * @return Key.
         */
        Key cryptoShortHashKeygen();

        /**
         * Hash a short message using a key.
         * @param in The short message to hash.
         * @param key The key generated via {@link #cryptoShortHashKeygen()}.
         * @return Your message hashed of size {@link #BYTES}, as hexadecimal string.
         */
        String cryptoShortHash(byte[] in, Key key) throws SodiumException;

        /**
         * Hash a short string using a key.
         * @param in The short message to hash.
         * @param key The key generated via {@link #cryptoShortHashKeygen()}.
         * @return Your message hashed of size {@link #BYTES}, as hexadecimal string.
         */
        String cryptoShortHashStr(String in, Key key) throws SodiumException;

        /**
         * Hash a short hexadecimal string using a key.
         * @param hexIn The short message to hash, represented as hexadecimal string.
         * @param key The key generated via {@link #cryptoShortHashKeygen()}.
         * @return Your message hashed of size {@link #BYTES}, as hexadecimal string.
         */
        String cryptoShortHashHex(String hexIn, Key key) throws SodiumException;


    }


}
