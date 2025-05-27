/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.interfaces;


import com.goterl.lazysodium.utils.BaseChecker;
import com.goterl.lazysodium.utils.DetachedDecrypt;
import com.goterl.lazysodium.utils.DetachedEncrypt;
import com.goterl.lazysodium.utils.Key;
import com.sun.jna.Structure;

import javax.crypto.AEADBadTagException;
import java.util.Arrays;
import java.util.List;

public interface AEAD {


    // REGULAR CHACHA

    int CHACHA20POLY1305_KEYBYTES = 32,
            CHACHA20POLY1305_NPUBBYTES = 8,
            CHACHA20POLY1305_ABYTES = 16;


    // IETF CHACHA

    int CHACHA20POLY1305_IETF_ABYTES = 16,
            CHACHA20POLY1305_IETF_KEYBYTES = 32,
            CHACHA20POLY1305_IETF_NPUBBYTES = 12;


    // This is XCHACHA not CHACHA.

    int XCHACHA20POLY1305_IETF_KEYBYTES = 32,
            XCHACHA20POLY1305_IETF_ABYTES = 16,
            XCHACHA20POLY1305_IETF_NPUBBYTES = 24;


    // AES256

    int AES256GCM_KEYBYTES = 32;
    int AES256GCM_NSECBYTES = 0;
    int AES256GCM_NPUBBYTES = 12;
    int AES256GCM_ABYTES = 16;


    enum Method {
        CHACHA20_POLY1305,
        CHACHA20_POLY1305_IETF,
        XCHACHA20_POLY1305_IETF,
        AES256GCM;

        @Deprecated
        public static final Method DEFAULT = AES256GCM;
    }


    interface Native {

        void cryptoAeadChaCha20Poly1305Keygen(byte[] key);

        /**
         * Encrypt a message
         *
         * @param cipher            Buffer for the cipher text
         * @param cipherLen         Output buffer into which the real length of the cipher text is stored (it can be {@code null} if not interested)
         * @param message           The message to encrypt
         * @param messageLen        Length of the message
         * @param additionalData    Additional authenticated data or {@code null}
         * @param additionalDataLen Length of additional authenticated data (or {@code 0})
         * @param nPub              Public nonce
         * @param key               Secret key
         * @return {@code true} if the encryption succeeded
         */
        boolean cryptoAeadChaCha20Poly1305Encrypt(
                byte[] cipher,
                long[] cipherLen,
                byte[] message,
                int messageLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        /**
         * Encrypt a message (a deprecated overload)
         *
         * @param cipher            Buffer for the cipher text
         * @param cipherLen         Output buffer into which the real length of the cipher text is stored (it can be {@code null} if not interested)
         * @param message           The message to encrypt
         * @param messageLen        Length of the message
         * @param additionalData    Additional authenticated data or {@code null}
         * @param additionalDataLen Length of additional authenticated data (or {@code 0})
         * @param nSec              Unused parameter; should be {@code null}
         * @param nPub              Public nonce
         * @param key               Secret key
         * @return {@code true} if the encryption succeeded
         * @deprecated Use {@link #cryptoAeadChaCha20Poly1305Encrypt(byte[], long[], byte[], int, byte[], int, byte[], byte[])} instead.
         */
        @Deprecated(forRemoval = true)
        boolean cryptoAeadChaCha20Poly1305Encrypt(
                byte[] cipher,
                long[] cipherLen,
                byte[] message,
                int messageLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nSec,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadChaCha20Poly1305Decrypt(
                byte[] message,
                long[] messageLen,
                byte[] cipher,
                int cipherLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        @Deprecated(forRemoval = true)
        boolean cryptoAeadChaCha20Poly1305Decrypt(
                byte[] message,
                long[] messageLen,
                byte[] nSec,
                byte[] cipher,
                int cipherLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadChaCha20Poly1305EncryptDetached(
                byte[] cipher,
                byte[] mac,
                long[] macLenAddress,
                byte[] message,
                int messageLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        @Deprecated(forRemoval = true)
        boolean cryptoAeadChaCha20Poly1305EncryptDetached(
                byte[] cipher,
                byte[] mac,
                long[] macLenAddress,
                byte[] message,
                int messageLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nSec,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadChaCha20Poly1305DecryptDetached(
                byte[] message,
                byte[] cipher,
                int cipherLen,
                byte[] mac,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        @Deprecated(forRemoval = true)
        boolean cryptoAeadChaCha20Poly1305DecryptDetached(
                byte[] message,
                byte[] nSec,
                byte[] cipher,
                int cipherLen,
                byte[] mac,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );


        // ietf

        void cryptoAeadChaCha20Poly1305IetfKeygen(byte[] key);

        boolean cryptoAeadChaCha20Poly1305IetfEncrypt(
                byte[] cipher,
                long[] cipherLen,
                byte[] message,
                int messageLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        @Deprecated(forRemoval = true)
        boolean cryptoAeadChaCha20Poly1305IetfEncrypt(
                byte[] cipher,
                long[] cipherLen,
                byte[] message,
                int messageLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nSec,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadChaCha20Poly1305IetfDecrypt(
                byte[] message,
                long[] messageLen,
                byte[] cipher,
                int cipherLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        @Deprecated(forRemoval = true)
        boolean cryptoAeadChaCha20Poly1305IetfDecrypt(
                byte[] message,
                long[] messageLen,
                byte[] nSec,
                byte[] cipher,
                int cipherLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadChaCha20Poly1305IetfEncryptDetached(
                byte[] cipher,
                byte[] mac,
                long[] macLenAddress,
                byte[] message,
                int messageLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        @Deprecated(forRemoval = true)
        boolean cryptoAeadChaCha20Poly1305IetfEncryptDetached(
                byte[] cipher,
                byte[] mac,
                long[] macLenAddress,
                byte[] message,
                int messageLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nSec,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadChaCha20Poly1305IetfDecryptDetached(
                byte[] message,
                byte[] cipher,
                int cipherLen,
                byte[] mac,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        @Deprecated(forRemoval = true)
        boolean cryptoAeadChaCha20Poly1305IetfDecryptDetached(
                byte[] message,
                byte[] nSec,
                byte[] cipher,
                int cipherLen,
                byte[] mac,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );


        // xchacha

        void cryptoAeadXChaCha20Poly1305IetfKeygen(byte[] key);

        boolean cryptoAeadXChaCha20Poly1305IetfEncrypt(
                byte[] cipher,
                long[] cipherLen,
                byte[] message,
                int messageLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        @Deprecated(forRemoval = true)
        boolean cryptoAeadXChaCha20Poly1305IetfEncrypt(
                byte[] cipher,
                long[] cipherLen,
                byte[] message,
                int messageLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nSec,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadXChaCha20Poly1305IetfDecrypt(
                byte[] message,
                long[] messageLen,
                byte[] cipher,
                int cipherLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        @Deprecated(forRemoval = true)
        boolean cryptoAeadXChaCha20Poly1305IetfDecrypt(
                byte[] message,
                long[] messageLen,
                byte[] nSec,
                byte[] cipher,
                int cipherLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadXChaCha20Poly1305IetfEncryptDetached(
                byte[] cipher,
                byte[] mac,
                long[] macLenAddress,
                byte[] message,
                int messageLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        @Deprecated(forRemoval = true)
        boolean cryptoAeadXChaCha20Poly1305IetfEncryptDetached(
                byte[] cipher,
                byte[] mac,
                long[] macLenAddress,
                byte[] message,
                int messageLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nSec,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadXChaCha20Poly1305IetfDecryptDetached(
                byte[] message,
                byte[] cipher,
                int cipherLen,
                byte[] mac,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        @Deprecated(forRemoval = true)
        boolean cryptoAeadXChaCha20Poly1305IetfDecryptDetached(
                byte[] message,
                byte[] nSec,
                byte[] cipher,
                int cipherLen,
                byte[] mac,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );


        // AES

        void cryptoAeadAES256GCMKeygen(byte[] key);

        boolean cryptoAeadAES256GCMEncrypt(
                byte[] cipher,
                long[] cipherLen,
                byte[] message,
                int messageLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        @Deprecated(forRemoval = true)
        boolean cryptoAeadAES256GCMEncrypt(
                byte[] cipher,
                long[] cipherLen,
                byte[] message,
                int messageLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nSec,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadAES256GCMDecrypt(
                byte[] message,
                long[] messageLen,
                byte[] cipher,
                int cipherLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        @Deprecated(forRemoval = true)
        boolean cryptoAeadAES256GCMDecrypt(
                byte[] message,
                long[] messageLen,
                byte[] nSec,
                byte[] cipher,
                int cipherLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadAES256GCMEncryptDetached(
                byte[] cipher,
                byte[] mac,
                long[] macLenAddress,
                byte[] message,
                int messageLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        @Deprecated(forRemoval = true)
        boolean cryptoAeadAES256GCMEncryptDetached(
                byte[] cipher,
                byte[] mac,
                long[] macLenAddress,
                byte[] message,
                int messageLen,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nSec,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadAES256GCMDecryptDetached(
                byte[] message,
                byte[] cipher,
                int cipherLen,
                byte[] mac,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        @Deprecated(forRemoval = true)
        boolean cryptoAeadAES256GCMDecryptDetached(
                byte[] message,
                byte[] nSec,
                byte[] cipher,
                int cipherLen,
                byte[] mac,
                byte[] additionalData,
                int additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadAES256GCMIsAvailable();

    }


    interface Lazy {

        Key keygen(Method method);

        String encrypt(String m,
                       String additionalData,
                       byte[] nPub,
                       Key k,
                       AEAD.Method method);

        @Deprecated(forRemoval = true)
        String encrypt(
                String m,
                String additionalData,
                byte[] nSec,
                byte[] nPub,
                Key k,
                Method method
        );

        String decrypt(
                String cipher,
                String additionalData,
                byte[] nPub,
                Key k,
                AEAD.Method method
        ) throws AEADBadTagException;

        @Deprecated(forRemoval = true)
        String decrypt(
                String cipher,
                String additionalData,
                byte[] nSec,
                byte[] nPub,
                Key k,
                Method method
        ) throws AEADBadTagException;

        DetachedEncrypt encryptDetached(
                String m,
                String additionalData,
                byte[] nPub,
                Key k,
                Method method
        );

        @Deprecated(forRemoval = true)
        DetachedEncrypt encryptDetached(
                String m,
                String additionalData,
                byte[] nSec,
                byte[] nPub,
                Key k,
                Method method
        );

        DetachedDecrypt decryptDetached(
                DetachedEncrypt detachedEncrypt,
                String additionalData,
                byte[] nPub,
                Key k,
                Method method
        ) throws AEADBadTagException;

        @Deprecated(forRemoval = true)
        DetachedDecrypt decryptDetached(
                DetachedEncrypt detachedEncrypt,
                String additionalData,
                byte[] nSec,
                byte[] nPub,
                Key k,
                Method method
        ) throws AEADBadTagException;


        // TODO: AES256-GCM with precomputation <https://doc.libsodium.org/secret-key_cryptography/aead/aes-256-gcm/aes-gcm_with_precomputation>
        // TODO: AEGIS-256 <https://doc.libsodium.org/secret-key_cryptography/aead/aegis-256>
        // TODO: AEGIS-128L <https://doc.libsodium.org/secret-key_cryptography/aead/aegis-128l>
    }


    class StateAES extends Structure {

        public static class ByReference extends StateAES implements Structure.ByReference {

        }

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("arr");
        }

        public byte[] arr = new byte[512];

    }


    final class Checker extends BaseChecker {
        private Checker() {
        }

        public static void checkChaCha20Poly1305Key(byte[] key) {
            checkExpectedMemorySize("key length", key.length, CHACHA20POLY1305_KEYBYTES);
        }

        public static void checkChaCha20Poly1305Nonce(byte[] nPub) {
            checkExpectedMemorySize("nPub length", nPub.length, CHACHA20POLY1305_NPUBBYTES);
        }

        public static void checkChaCha20Poly1305CipherLength(byte[] cipher, int messageLength, boolean receivesCipherLen) {
            if (receivesCipherLen) {
                BaseChecker.checkAtLeast("cipher length", cipher.length, messageLength + AEAD.CHACHA20POLY1305_ABYTES);
            } else {
                checkExpectedMemorySize("cipher length", cipher.length, messageLength + AEAD.CHACHA20POLY1305_ABYTES);
            }
        }

        public static void checkChaCha20Poly1305DecryptedMessageLength(byte[] message, int cipherLength, boolean receivesMessageLen) {
            BaseChecker.checkAtLeast("cipherLength", cipherLength, AEAD.CHACHA20POLY1305_ABYTES);
            if (receivesMessageLen) {
                BaseChecker.checkAtLeast("message length", message.length, cipherLength - AEAD.CHACHA20POLY1305_ABYTES);
            } else {
                checkExpectedMemorySize("message length", message.length, cipherLength - AEAD.CHACHA20POLY1305_ABYTES);
            }
        }

        public static void checkChaCha20Poly1305Mac(byte[] mac, boolean receivesMacLen) {
            if (receivesMacLen) {
                BaseChecker.checkAtLeast("mac length", mac.length, AEAD.CHACHA20POLY1305_ABYTES);
            } else {
                checkExpectedMemorySize("mac length", mac.length, AEAD.CHACHA20POLY1305_ABYTES);
            }
        }


        public static void checkChaCha20Poly1305IetfKey(byte[] key) {
            checkExpectedMemorySize("key length", key.length, CHACHA20POLY1305_IETF_KEYBYTES);
        }

        public static void checkChaCha20Poly1305IetfNonce(byte[] nPub) {
            checkExpectedMemorySize("nPub length", nPub.length, CHACHA20POLY1305_IETF_NPUBBYTES);
        }

        public static void checkChaCha20Poly1305IetfCipherLength(byte[] cipher, int messageLength, boolean receivesCipherLen) {
            if (receivesCipherLen) {
                BaseChecker.checkAtLeast("cipher length", cipher.length, messageLength + AEAD.CHACHA20POLY1305_IETF_ABYTES);
            } else {
                checkExpectedMemorySize("cipher length", cipher.length, messageLength + AEAD.CHACHA20POLY1305_IETF_ABYTES);
            }
        }

        public static void checkChaCha20Poly1305IetfDecryptedMessageLength(byte[] message, int cipherLength, boolean receivesMessageLen) {
            BaseChecker.checkAtLeast("cipherLength", cipherLength, AEAD.CHACHA20POLY1305_IETF_ABYTES);
            if (receivesMessageLen) {
                BaseChecker.checkAtLeast("message length", message.length, cipherLength - AEAD.CHACHA20POLY1305_IETF_ABYTES);
            } else {
                checkExpectedMemorySize("message length", message.length, cipherLength - AEAD.CHACHA20POLY1305_IETF_ABYTES);
            }
        }

        public static void checkChaCha20Poly1305IetfMac(byte[] mac, boolean receivesMacLen) {
            if (receivesMacLen) {
                BaseChecker.checkAtLeast("mac length", mac.length, AEAD.CHACHA20POLY1305_IETF_ABYTES);
            } else {
                checkExpectedMemorySize("mac length", mac.length, AEAD.CHACHA20POLY1305_IETF_ABYTES);
            }
        }

        public static void checkXChaCha20Poly1305IetfKey(byte[] key) {
            checkExpectedMemorySize("key length", key.length, XCHACHA20POLY1305_IETF_KEYBYTES);
        }

        public static void checkXChaCha20Poly1305IetfNonce(byte[] nPub) {
            checkExpectedMemorySize("nPub length", nPub.length, XCHACHA20POLY1305_IETF_NPUBBYTES);
        }

        public static void checkXChaCha20Poly1305IetfCipherLength(byte[] cipher, int messageLength, boolean receivesCipherLen) {
            if (receivesCipherLen) {
                BaseChecker.checkAtLeast("cipher length", cipher.length, messageLength + AEAD.XCHACHA20POLY1305_IETF_ABYTES);
            } else {
                checkExpectedMemorySize("cipher length", cipher.length, messageLength + AEAD.XCHACHA20POLY1305_IETF_ABYTES);
            }
        }

        public static void checkXChaCha20Poly1305IetfDecryptedMessageLength(byte[] message, int cipherLength, boolean receivesMessageLen) {
            BaseChecker.checkAtLeast("cipherLength", cipherLength, AEAD.XCHACHA20POLY1305_IETF_ABYTES);
            if (receivesMessageLen) {
                BaseChecker.checkAtLeast("message length", message.length, cipherLength - AEAD.XCHACHA20POLY1305_IETF_ABYTES);
            } else {
                checkExpectedMemorySize("message length", message.length, cipherLength - AEAD.XCHACHA20POLY1305_IETF_ABYTES);
            }
        }

        public static void checkXChaCha20Poly1305IetfMac(byte[] mac, boolean receivesMacLen) {
            if (receivesMacLen) {
                BaseChecker.checkAtLeast("mac length", mac.length, AEAD.XCHACHA20POLY1305_IETF_ABYTES);
            } else {
                checkExpectedMemorySize("mac length", mac.length, AEAD.XCHACHA20POLY1305_IETF_ABYTES);
            }
        }

        public static void checkAes256GcmKey(byte[] key) {
            checkExpectedMemorySize("key length", key.length, AES256GCM_KEYBYTES);
        }

        public static void checkAes256GcmNonce(byte[] nPub) {
            checkExpectedMemorySize("nPub length", nPub.length, AES256GCM_NPUBBYTES);
        }

        public static void checkAes256GcmCipherLength(byte[] cipher, int messageLength, boolean receivesCipherLen) {
            if (receivesCipherLen) {
                BaseChecker.checkAtLeast("cipher length", cipher.length, messageLength + AEAD.AES256GCM_ABYTES);
            } else {
                checkExpectedMemorySize("cipher length", cipher.length, messageLength + AEAD.AES256GCM_ABYTES);
            }
        }

        public static void checkAes256GcmDecryptedMessageLength(byte[] message, int cipherLength, boolean receivesMessageLen) {
            BaseChecker.checkAtLeast("cipherLength", cipherLength, AEAD.AES256GCM_ABYTES);
            if (receivesMessageLen) {
                BaseChecker.checkAtLeast("message length", message.length, cipherLength - AEAD.AES256GCM_ABYTES);
            } else {
                checkExpectedMemorySize("message length", message.length, cipherLength - AEAD.AES256GCM_ABYTES);
            }
        }

        public static void checkAes256GcmMac(byte[] mac, boolean receivesMacLen) {
            if (receivesMacLen) {
                BaseChecker.checkAtLeast("mac length", mac.length, AEAD.AES256GCM_ABYTES);
            } else {
                checkExpectedMemorySize("mac length", mac.length, AEAD.AES256GCM_ABYTES);
            }
        }

    }

}
