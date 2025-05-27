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
import com.goterl.lazysodium.utils.Constants;
import com.sun.jna.NativeLong;

import java.util.HashMap;
import java.util.Map;

import static com.goterl.lazysodium.utils.Constants.UNSIGNED_INT;

public interface PwHash {


    // Argon2 constants

    int ARGON2ID_SALTBYTES = 16,
        ARGON2ID_BYTES_MIN = 16,
        ARGON2ID_STR_BYTES = 128,
        SALTBYTES = ARGON2ID_SALTBYTES,
        STR_BYTES = ARGON2ID_STR_BYTES;

    long
        ARGON2ID_OPSLIMIT_MIN = 1L,
        ARGON2ID_OPSLIMIT_MAX = Constants.UNSIGNED_INT,
        ARGON2ID_OPSLIMIT_INTERACTIVE = 2L,
        ARGON2ID_OPSLIMIT_MODERATE = 3L,
        ARGON2ID_OPSLIMIT_SENSITIVE = 4L,
        OPSLIMIT_MIN = ARGON2ID_OPSLIMIT_MIN,
        OPSLIMIT_MAX = ARGON2ID_OPSLIMIT_MAX,
        OPSLIMIT_MODERATE = ARGON2ID_OPSLIMIT_MODERATE,
        OPSLIMIT_INTERACTIVE = ARGON2ID_OPSLIMIT_INTERACTIVE,
        OPSLIMIT_SENSITIVE = ARGON2ID_OPSLIMIT_SENSITIVE;


    int
        ARGON2ID_MEMLIMIT_MIN = 8192,
        ARGON2ID_MEMLIMIT_MAX = UNSIGNED_INT,
        ARGON2ID_MEMLIMIT_INTERACTIVE = 67108864, // 67 megabytes
        ARGON2ID_MEMLIMIT_MODERATE = 268435456, // 268 megabytes
        ARGON2ID_MEMLIMIT_SENSITIVE = 1073741824, // 1 gigabyte
        ARGON2ID_PASSWD_MIN = 0,
        ARGON2ID_PASSWD_MAX = Constants.UNSIGNED_INT,
        ARGON2ID_BYTES_MAX = Constants.UNSIGNED_INT,

        PASSWD_MIN = ARGON2ID_PASSWD_MIN,
        PASSWD_MAX = ARGON2ID_PASSWD_MAX,

        BYTES_MIN = ARGON2ID_BYTES_MIN,
        BYTES_MAX = ARGON2ID_BYTES_MAX;

    NativeLong
            MEMLIMIT_MIN = new NativeLong(ARGON2ID_MEMLIMIT_MIN),
            MEMLIMIT_INTERACTIVE = new NativeLong(ARGON2ID_MEMLIMIT_INTERACTIVE),
            MEMLIMIT_SENSITIVE = new NativeLong(ARGON2ID_MEMLIMIT_SENSITIVE),
            MEMLIMIT_MODERATE = new NativeLong(ARGON2ID_MEMLIMIT_MODERATE),
            MEMLIMIT_MAX = new NativeLong(ARGON2ID_MEMLIMIT_MAX);




    interface Native {

        /**
         * Based on a password you provide, hash that
         * password and put the output into {@code outputHash}.
         *
         * Take note that the output of this does NOT output a traditional
         * Argon 2 string as the underlying native implementation calls argon2id_hash_raw
         * instead of argon2id_hash_encoded. If you want an Argon 2 encoded string please refer
         * to {@link #cryptoPwHashStr(byte[], byte[], int, long, NativeLong)} instead.
         * @param outputHash Where to store the resulting password hash.
         * @param outputHashLen The password hash's length. Must be at least {@link PwHash#BYTES_MIN}.
         * @param password The password that you want to hash.
         * @param passwordLen The length of the password's bytes.
         * @param salt A salt that's randomly generated.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link PwHash#OPSLIMIT_MIN} and {@link PwHash#OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link PwHash#MEMLIMIT_MIN} and {@link PwHash#MEMLIMIT_MAX}.
         * @param alg The algorithm to use. Please use {@link PwHash.Alg#PWHASH_ALG_ARGON2ID13} for now.
         * @return True if the hash succeeded.
         */
        boolean cryptoPwHash(byte[] outputHash,
                             int outputHashLen,
                             byte[] password,
                             int passwordLen,
                             byte[] salt,
                             long opsLimit,
                             NativeLong memLimit,
                             Alg alg);

        /**
         * Hashes a password and stores it into an array. The output is
         * an ASCII encoded string in a byte array.
         * @param outputStr An array to hold the hash. Must be at least {@link PwHash#STR_BYTES}.
         * @param password A password that you want to hash.
         * @param passwordLen The password's byte length.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link PwHash#OPSLIMIT_MIN} and {@link PwHash#OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link PwHash#MEMLIMIT_MIN} and {@link PwHash#MEMLIMIT_MAX}.
         * @return True if the hash succeeded.
         * @see #cryptoPwHashStrVerify(byte[], byte[], int)
         */
        boolean cryptoPwHashStr(byte[] outputStr,
                              byte[] password,
                              int passwordLen,
                              long opsLimit,
                               NativeLong memLimit);

        /**
         * Verifies a hashed password. Remember: you must add
         * a null byte to the end of the hash so that this works properly!
         *
         * @param hash The hash of the password.
         * @param password The password to check if it equals the hash's password.
         * @param passwordLen The checking password's length.
         * @return True if the password matches the unhashed hash.
         */
        boolean cryptoPwHashStrVerify(byte[] hash, byte[] password, int passwordLen);


        /**
         * Checks whether the hash needs a rehash.
         * @param hash The hash.
         * @param opsLimit The operations limit used.
         * @param memLimit The memory limit used.
         * @return Whether the hash should be rehashed.
         */
        NeedsRehashResult cryptoPwHashStrNeedsRehash(byte[] hash, long opsLimit, NativeLong memLimit);



    }

    interface Lazy {

        /**
         * Hashes a given password.
         * @param cryptoPwHashLen The hash size that you want.
         *                     Anything between {@link #BYTES_MIN} and {@link #BYTES_MAX}
         * @param password The password to hash.
         * @param salt A salt to use with the hash, generated randomly.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link PwHash#OPSLIMIT_MIN} and {@link PwHash#OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link PwHash#MEMLIMIT_MIN} and {@link PwHash#MEMLIMIT_MAX}.
         * @param alg The algorithm to use. Defaults to {@link PwHash.Alg#PWHASH_ALG_ARGON2ID13}.
         * @return A hash of the password in bytes, encoded to string.
         * @throws SodiumException If the password is too short or the opsLimit is not correct.
         */
        String cryptoPwHash(String password,
                            int cryptoPwHashLen,
                            byte[] salt,
                            long opsLimit,
                            NativeLong memLimit,
                            Alg alg) throws SodiumException;


        /**
         * The most minimal way of hashing a given password to a standard-format string including all used parameters.
         * We auto-generate the salt and use the default hashing algorithm {@link PwHash.Alg}.
         * @param password The password string to hash.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link PwHash#OPSLIMIT_MIN}
         *                 and {@link PwHash#OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link PwHash#MEMLIMIT_MIN}
         *                 and {@link PwHash#MEMLIMIT_MAX}.
         * @return The hashed password in a standard format, including all used parameters.
         * @throws SodiumException If the password could not be hashed.
         * @see #cryptoPwHashStringVerify(String, String)
         */
        String cryptoPwHashString(String password,
                                  long opsLimit,
                                  NativeLong memLimit) throws SodiumException;


        /**
         * The most minimal way of hashing a given password to a string including all used parameters.
         * We auto-generate the salt and use the default hashing algorithm {@link PwHash.Alg}.
         * @param password The password string to hash.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link PwHash#OPSLIMIT_MIN}
         *                 and {@link PwHash#OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link PwHash#MEMLIMIT_MIN}
         *                 and {@link PwHash#MEMLIMIT_MAX}.
         * @return The hashed password represented as a long encoded string, which includes useless null bytes.
         * @throws SodiumException If the password could not be hashed.
         * @see #cryptoPwHashStrRemoveNulls(String, long, NativeLong)
         * @see #cryptoPwHashStrVerify(String, String)
         * @deprecated Uses dumb result format; use {@link #cryptoPwHashString(String, long, NativeLong)} instead.
         */
        @Deprecated
        String cryptoPwHashStr(String password,
                               long opsLimit,
                               NativeLong memLimit) throws SodiumException;


        /**
         * Hashes a string to a string representation including the used parameters, and removes all
         * useless null bytes. Uses the hashing algorithm {@link PwHash.Alg}.
         * @param password The password string to hash.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link PwHash#OPSLIMIT_MIN}
         *                 and {@link PwHash#OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link PwHash#MEMLIMIT_MIN}
         *                 and {@link PwHash#MEMLIMIT_MAX}.
         * @return The hash and all used parameters represented as a long hexadecimal string.
         * @throws SodiumException If the password could not be hashed.
         * @see #cryptoPwHashStrVerify(String, String)
         * @deprecated Uses dumb result format; use {@link #cryptoPwHashString(String, long, NativeLong)} instead.
         */
        @Deprecated
        String cryptoPwHashStrRemoveNulls(String password,
                                          long opsLimit,
                                          NativeLong memLimit) throws SodiumException;


        /**
         * Verifies a password represented as a long encoded string generated by {@link #cryptoPwHashStr(String, long, NativeLong)}
         * or {@link #cryptoPwHashStrRemoveNulls(String, long, NativeLong)}.
         * @param hash The encoded hash generated by {@link #cryptoPwHashStr(String, long, NativeLong)} or {@link #cryptoPwHashStrRemoveNulls(String, long, NativeLong)}
         * @param password The password.
         * @return True if the password matches the hash, false otherwise.
         * @deprecated Uses dumb hash format; use {@link #cryptoPwHashStringVerify(String, String)} instead.
         */
        @Deprecated
        boolean cryptoPwHashStrVerify(String hash, String password);


        /**
         * Verifies a password represented as a standard-formatted hash, generated by {@link #cryptoPwHashString(String, long, NativeLong)}.
         * @param hash Standard-formatted hash
         * @param password The password.
         * @return True if the password matches the hash, false otherwise.
         */
        boolean cryptoPwHashStringVerify(String hash, String password);

        /**
         * Checks whether the hash needs a rehash.
         * @param hash Standard-formatted hash generated by {@link #cryptoPwHashString(String, long, NativeLong)}.
         * @param opsLimit The operations limit which should be used.
         * @param memLimit The memory limit which should be used.
         * @return Whether the hash should be rehashed.
         */
        NeedsRehashResult cryptoPwHashStringNeedsRehash(String hash, long opsLimit, NativeLong memLimit);
    }


    enum Alg {
        PWHASH_ALG_ARGON2I13(1),
        PWHASH_ALG_ARGON2ID13(2);

        private final int val;

        Alg(final int val) {
            this.val = val;
        }

        public int getValue() {
            return val;
        }

        public static Alg getDefault() {
            return PWHASH_ALG_ARGON2ID13;
        }

        public static Alg valueOf(int alg) {
            return map.get(alg);
        }

        private final static Map<Integer, Alg> map = getMap();

        private static Map<Integer, Alg> getMap() {
            Map<Integer, Alg> map = new HashMap<>();
            for (Alg alg : Alg.values()) {
                map.put(alg.val, alg);
            }
            return map;
        }
    }

    /**
     * Possible results of *NeedsRehash functions
     */
    enum NeedsRehashResult {
        /**
         * The parameters already match, no rehash is needed.
         */
        NO_REHASH_NEEDED(0),

        /**
         * The string appears to be a valid hash but does not match the requested parameters; a new hash should
         * be computed the next time the user logs in.
         */
        NEEDS_REHASH(1),

        /**
         * The string does not appear to be a valid hash.
         */
        INVALID_HASH(-1);

        private final int val;

        NeedsRehashResult(int val) {
            this.val = val;
        }

        public static NeedsRehashResult valueOf(int alg) {
            NeedsRehashResult result = map.get(alg);
            if (result == null) {
                // should not happen
                return INVALID_HASH;
            }
            return result;
        }

        private final static Map<Integer, NeedsRehashResult> map = getMap();

        private static Map<Integer, NeedsRehashResult> getMap() {
            Map<Integer, NeedsRehashResult> map = new HashMap<>();
            for (NeedsRehashResult alg : NeedsRehashResult.values()) {
                map.put(alg.val, alg);
            }
            return map;
        }
    }

    final class Checker extends BaseChecker {
        private Checker() {}

        public static void checkLengthOfHash(int lengthOfHash) {
            checkBetween("hash length", lengthOfHash, PwHash.BYTES_MIN, PwHash.BYTES_MAX);
        }

        public static void checkHashStrOutput(byte[] outputStr) {
            checkAtLeast("outputStr length", outputStr.length, PwHash.STR_BYTES);
        }

        public static void checkPassword(byte[] password) {
            checkLengthOfPassword(password.length);
        }

        public static void checkLengthOfPassword(int lengthOfPassword) {
            checkBetween("password length", lengthOfPassword, PwHash.PASSWD_MIN, PwHash.PASSWD_MAX);
        }

        public static void checkSalt(byte[] salt) {
            checkExpectedMemorySize("salt length", salt.length, SALTBYTES);
        }

        public static void checkOpsLimit(long opsLimit) {
            checkBetween("opsLimit", opsLimit, PwHash.OPSLIMIT_MIN, PwHash.OPSLIMIT_MAX);
        }

        public static void checkMemLimit(NativeLong memLimit) {
            checkBetween("memLimit", memLimit, PwHash.MEMLIMIT_MIN, PwHash.MEMLIMIT_MAX);
        }

        public static void checkHashStrInput(byte[] hashStrBytes) {
            int maxHashLen = Math.min(hashStrBytes.length, PwHash.STR_BYTES);
            for (int i = 0; i < maxHashLen; ++i) {
                if (hashStrBytes[i] == 0) {
                    return;
                }
            }
            if (maxHashLen == hashStrBytes.length) {
                throw new IllegalArgumentException("Hash is not null terminated");
            } else {
                throw new IllegalArgumentException("Hash is too long or not null terminated");
            }
        }
    }

}
