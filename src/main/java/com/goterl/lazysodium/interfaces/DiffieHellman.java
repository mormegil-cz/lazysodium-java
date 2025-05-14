/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.interfaces;


import com.goterl.lazysodium.utils.BaseChecker;
import com.goterl.lazysodium.utils.Key;

public interface DiffieHellman {

    int SCALARMULT_CURVE25519_BYTES = 32;
    int SCALARMULT_CURVE25519_SCALARBYTES = 32;

    int SCALARMULT_BYTES = SCALARMULT_CURVE25519_BYTES;
    int SCALARMULT_SCALARBYTES = SCALARMULT_CURVE25519_SCALARBYTES;


    class Checker extends BaseChecker {
        public static void checkPublicKey(byte[] publicKey) {
            checkExpectedMemorySize("publicKey", SCALARMULT_BYTES, publicKey.length);
        }

        public static void checkSecretKey(byte[] secretKey) {
            checkExpectedMemorySize("secretKey", SCALARMULT_SCALARBYTES, secretKey.length);
        }

        public static void checkSharedKey(byte[] sharedKey) {
            checkExpectedMemorySize("sharedKey", SCALARMULT_BYTES, sharedKey.length);
        }

    }


    interface Native {

        boolean cryptoScalarMultBase(byte[] publicKey, byte[] secretKey);
        boolean cryptoScalarMult(byte[] shared, byte[] secretKey, byte[] publicKey);

    }



    interface Lazy {

        /**
         * Generate a public key from a private key.
         * @param secretKey Provide the secret key.
         * @return The public key and the provided secret key.
         */
        Key cryptoScalarMultBase(Key secretKey);


        /**
         * Generate a shared key from another user's public key
         * and a secret key.
         * @param secretKey A secret key.
         * @param publicKey Another user's public key.
         * @return Shared secret key.
         */
        Key cryptoScalarMult(Key secretKey, Key publicKey);

    }

}
