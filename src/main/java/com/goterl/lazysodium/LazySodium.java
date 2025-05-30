/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.*;
import com.goterl.lazysodium.interfaces.Ristretto255.RistrettoPoint;
import com.goterl.lazysodium.utils.*;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

import javax.crypto.AEADBadTagException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public abstract class LazySodium implements
        Base,
        Random,
        AEAD.Native, AEAD.Lazy,
        GenericHash.Native, GenericHash.Lazy,
        ShortHash.Native, ShortHash.Lazy,
        SecureMemory.Native, SecureMemory.Lazy,
        Auth.Native, Auth.Lazy,
        SecretStream.Native, SecretStream.Lazy,
        Stream.Native, Stream.Lazy,
        Padding.Native, Padding.Lazy,
        Helpers.Native, Helpers.Lazy,
        PwHash.Native, PwHash.Lazy,
        Hash.Native, Hash.Lazy,
        Sign.Native, Sign.Lazy,
        Box.Native, Box.Lazy,
        SecretBox.Native, SecretBox.Lazy,
        KeyExchange.Native, KeyExchange.Lazy,
        KeyDerivation.Native, KeyDerivation.Lazy,
        DiffieHellman.Native, DiffieHellman.Lazy,
        Ristretto255.Native, Ristretto255.Lazy {

    protected final Charset charset;
    protected final MessageEncoder messageEncoder;

    public LazySodium() {
        this(StandardCharsets.UTF_8, new HexMessageEncoder());
    }

    public LazySodium(Charset charset) {
        this(charset, new HexMessageEncoder());
    }

    public LazySodium(MessageEncoder messageEncoder) {
        this(StandardCharsets.UTF_8, messageEncoder);
    }

    public LazySodium(Charset charset, MessageEncoder messageEncoder) {
        this.charset = charset;
        this.messageEncoder = messageEncoder;
    }


    //// -------------------------------------------|
    //// HELPERS
    //// -------------------------------------------|

    @Override
    public int sodiumInit() {
        return getSodium().sodium_init();
    }

    @Override
    public String sodiumBin2Hex(byte[] bin) {
        return bytesToHex(bin);
    }

    @Override
    public byte[] sodiumHex2Bin(String hex) {
        return hexToBytes(hex);
    }

    public String toHexStr(byte[] bs) {
        return bytesToHex(bs);
    }

    public byte[] toBinary(String hex) {
        return hexToBytes(hex);
    }

    /**
     * Bytes to hexadecimal. Equivalent to {@link #sodiumBin2Hex(byte[])} but static.
     *
     * @param bin Byte array.
     * @return Hexadecimal string.
     */
    public static String toHex(byte[] bin) {
        return bytesToHex(bin);
    }


    /**
     * Hexadecimal string to bytes. Equivalent to {@link #sodiumHex2Bin(String)}} but static.
     *
     * @param hex Hexadecimal string to convert to bytes.
     * @return Byte array.
     */
    public static byte[] toBin(String hex) {
        return hexToBytes(hex);
    }


    private static final char[] hexArray = "0123456789ABCDEF".toCharArray();

    // The following is from https://stackoverflow.com/a/9855338/3526705
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static byte[] hexToBytes(String s) {
        int len = s.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("Hexadecimal string length must be even");
        }
        byte[] data = new byte[len / 2];
        for (int i = 0; i < data.length; ++i) {
            data[i] = (byte) ((hexDigit(s.charAt(2 * i)) & 0xFF) << 4 | (hexDigit(s.charAt(2 * i + 1)) & 0xFF));
        }
        return data;
    }

    private static byte hexDigit(char c) {
        if (c >= '0' && c <= '9') {
            return (byte) (c - '0');
        }
        if (c >= 'A' && c <= 'F') {
            return (byte) (c - 'A' + 10);
        }
        if (c >= 'a' && c <= 'f') {
            return (byte) (c - 'a' + 10);
        }
        throw new IllegalArgumentException("Illegal hexadecimal character " + (byte) (c));
    }


    //// -------------------------------------------|
    //// RANDOM
    //// -------------------------------------------|

    @Override
    public long randomBytesRandom() {
        return getSodium().randombytes_random();
    }

    @Override
    public void randomBytesBuf(byte[] buff, int size) {
        BaseChecker.checkArrayLength("buff", buff, size);
        getSodium().randombytes_buf(buff, size);
    }

    @Override
    public byte[] randomBytesBuf(int size) {
        byte[] bs = new byte[size];
        getSodium().randombytes_buf(bs, size);
        return bs;
    }

    @Override
    public byte[] nonce(int size) {
        return randomBytesBuf(size);
    }

    @Override
    public long randomBytesUniform(int upperBound) {
        return getSodium().randombytes_uniform(upperBound);
    }

    @Override
    public void randomBytesDeterministic(byte[] buff, int size, byte[] seed) {
        BaseChecker.checkArrayLength("buff", buff, size);
        RandomChecker.checkSeed(seed);
        getSodium().randombytes_buf_deterministic(buff, size, seed);
    }

    @Override
    public byte[] randomBytesDeterministic(int size, byte[] seed) {
        RandomChecker.checkSeed(seed);
        byte[] bs = new byte[size];
        getSodium().randombytes_buf_deterministic(bs, size, seed);
        return bs;
    }


    //// -------------------------------------------|
    //// PADDING
    //// -------------------------------------------|

    @Override
    public boolean sodiumPad(IntByReference paddedBuffLen, Pointer buf, int unpaddedBufLen, int blockSize, int maxBufLen) {
        return successful(getSodium().sodium_pad(paddedBuffLen, buf, unpaddedBufLen, blockSize, maxBufLen));
    }

    @Override
    public boolean sodiumUnpad(IntByReference unPaddedBuffLen, Pointer buf, int paddedBufLen, int blockSize) {
        return successful(getSodium().sodium_unpad(unPaddedBuffLen, buf, paddedBufLen, blockSize));
    }


    //// -------------------------------------------|
    //// SECURE MEMORY
    //// -------------------------------------------|

    @Override
    public void sodiumMemZero(byte[] pnt, int len) {
        BaseChecker.checkArrayLength("pnt", pnt, len);
        getSodium().sodium_memzero(pnt, len);
    }

    @Override
    public boolean sodiumMLock(byte[] array, int len) {
        BaseChecker.checkArrayLength("array", array, len);
        return successful(getSodium().sodium_mlock(array, len));
    }

    @Override
    public boolean sodiumMUnlock(byte[] array, int len) {
        BaseChecker.checkArrayLength("array", array, len);
        return successful(getSodium().sodium_munlock(array, len));

    }

    @Override
    public Pointer sodiumMalloc(int size) {
        BaseChecker.checkAtLeast("size", size, 0);
        return getSodium().sodium_malloc(size);
    }

    @Override
    public Pointer sodiumAllocArray(int count, int size) {
        BaseChecker.checkAtLeast("count", count, 0);
        BaseChecker.checkAtLeast("size", size, 0);
        return getSodium().sodium_allocarray(count, size);
    }

    @Override
    public void sodiumFree(Pointer p) {
        getSodium().sodium_free(p);
    }

    @Override
    public boolean sodiumMProtectNoAccess(Pointer ptr) {
        return successful(getSodium().sodium_mprotect_noaccess(ptr));
    }

    @Override
    public boolean sodiumMProtectReadOnly(Pointer ptr) {
        return successful(getSodium().sodium_mprotect_readonly(ptr));
    }

    @Override
    public boolean sodiumMProtectReadWrite(Pointer ptr) {
        return successful(getSodium().sodium_mprotect_readwrite(ptr));
    }


    //// -------------------------------------------|
    //// KDF KEYGEN
    //// -------------------------------------------|

    @Override
    public void cryptoKdfKeygen(byte[] masterKey) {
        KeyDerivation.Checker.checkMasterKey(masterKey);
        getSodium().crypto_kdf_keygen(masterKey);
    }

    @Override
    public boolean cryptoKdfDeriveFromKey(byte[] subKey, int subKeyLen, long subKeyId, byte[] context, byte[] masterKey) {
        KeyDerivation.Checker.checkSubKeyLength(subKeyLen);
        BaseChecker.checkArrayLength("subKey", subKey, subKeyLen);
        KeyDerivation.Checker.checkMasterKey(masterKey);
        KeyDerivation.Checker.checkContext(context);
        return successful(getSodium().crypto_kdf_derive_from_key(subKey, subKeyLen, subKeyId, context, masterKey));
    }

    @Override
    public Key cryptoKdfKeygen() {
        byte[] masterKey = new byte[KeyDerivation.MASTER_KEY_BYTES];
        getSodium().crypto_kdf_keygen(masterKey);
        return Key.fromBytes(masterKey);
    }

    @Override
    public Key cryptoKdfDeriveFromKey(int lengthOfSubKey, long subKeyId, String context, Key masterKey)
            throws SodiumException {
        KeyDerivation.Checker.checkSubKeyLength(lengthOfSubKey);
        KeyDerivation.Checker.checkMasterKey(masterKey.getAsBytes());
        byte[] contextAsBytes = bytes(context);
        KeyDerivation.Checker.checkContext(contextAsBytes);

        byte[] subKey = new byte[lengthOfSubKey];
        byte[] masterKeyAsBytes = masterKey.getAsBytes();
        int res = getSodium().crypto_kdf_derive_from_key(
                subKey,
                lengthOfSubKey,
                subKeyId,
                contextAsBytes,
                masterKeyAsBytes
        );

        if (!successful(res)) {
            throw new SodiumException("Failed cryptoKdfDeriveFromKey.");
        }
        return Key.fromBytes(subKey);
    }


    //// -------------------------------------------|
    //// KEY EXCHANGE
    //// -------------------------------------------|

    @Override
    public boolean cryptoKxKeypair(byte[] publicKey, byte[] secretKey) {
        KeyExchange.Checker.checkPublicKey(publicKey);
        KeyExchange.Checker.checkSecretKey(secretKey);
        return successful(getSodium().crypto_kx_keypair(publicKey, secretKey));
    }

    @Override
    public boolean cryptoKxSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed) {
        KeyExchange.Checker.checkPublicKey(publicKey);
        KeyExchange.Checker.checkSecretKey(secretKey);
        KeyExchange.Checker.checkSeed(seed);
        return successful(getSodium().crypto_kx_seed_keypair(publicKey, secretKey, seed));
    }

    @Override
    public boolean cryptoKxClientSessionKeys(byte[] rx, byte[] tx, byte[] clientPk, byte[] clientSk, byte[] serverPk) {
        KeyExchange.Checker.checkSessionKey(rx);
        KeyExchange.Checker.checkSessionKey(tx);
        KeyExchange.Checker.checkPublicKey(clientPk);
        KeyExchange.Checker.checkSecretKey(clientSk);
        KeyExchange.Checker.checkPublicKey(serverPk);
        return successful(getSodium().crypto_kx_client_session_keys(rx, tx, clientPk, clientSk, serverPk));
    }

    @Override
    public boolean cryptoKxServerSessionKeys(byte[] rx, byte[] tx, byte[] serverPk, byte[] serverSk, byte[] clientPk) {
        KeyExchange.Checker.checkSessionKey(rx);
        KeyExchange.Checker.checkSessionKey(tx);
        KeyExchange.Checker.checkPublicKey(serverPk);
        KeyExchange.Checker.checkSecretKey(serverSk);
        KeyExchange.Checker.checkPublicKey(clientPk);
        return successful(getSodium().crypto_kx_server_session_keys(rx, tx, serverPk, serverSk, clientPk));
    }


    // -- Lazy functions

    @Override
    public KeyPair cryptoKxKeypair() throws SodiumException {
        byte[] secretKey = new byte[KeyExchange.SECRETKEYBYTES];
        byte[] publicKey = new byte[KeyExchange.PUBLICKEYBYTES];

        if (!successful(getSodium().crypto_kx_keypair(publicKey, secretKey))) {
            throw new SodiumException("Failed to generate keypair");
        }

        return new KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secretKey));
    }

    @Override
    public KeyPair cryptoKxKeypair(byte[] seed) throws SodiumException {
        KeyExchange.Checker.checkSeed(seed);
        byte[] secretKey = new byte[KeyExchange.SECRETKEYBYTES];
        byte[] publicKey = new byte[KeyExchange.PUBLICKEYBYTES];

        if (!successful(getSodium().crypto_kx_seed_keypair(publicKey, secretKey, seed))) {
            throw new SodiumException("Failed to generate keypair");
        }

        return new KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secretKey));
    }

    @Override
    @Deprecated(forRemoval = true, since = "6.0.0")
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    public SessionPair cryptoKxClientSessionKeys(KeyPair clientKeyPair, KeyPair serverKeyPair) throws SodiumException {
        return cryptoKxClientSessionKeys(clientKeyPair.getPublicKey(), clientKeyPair.getSecretKey(), serverKeyPair.getPublicKey());
    }

    @Override
    public SessionPair cryptoKxClientSessionKeys(KeyPair clientKeyPair, Key serverPublicKey) throws SodiumException {
        return cryptoKxClientSessionKeys(clientKeyPair.getPublicKey(), clientKeyPair.getSecretKey(), serverPublicKey);
    }

    @Override
    public SessionPair cryptoKxServerSessionKeys(Key serverPk, Key serverSk, Key clientPk) throws SodiumException {
        byte[] rx = new byte[KeyExchange.SESSIONKEYBYTES];
        byte[] tx = new byte[KeyExchange.SESSIONKEYBYTES];

        if (!cryptoKxServerSessionKeys(rx, tx, serverPk.getAsBytes(), serverSk.getAsBytes(), clientPk.getAsBytes())) {
            throw new SodiumException("Failed creating server session keys.");
        }

        return new SessionPair(rx, tx);
    }

    @Override
    public SessionPair cryptoKxClientSessionKeys(Key clientPk, Key clientSk, Key serverPk) throws SodiumException {
        byte[] rx = new byte[KeyExchange.SESSIONKEYBYTES];
        byte[] tx = new byte[KeyExchange.SESSIONKEYBYTES];

        if (!cryptoKxClientSessionKeys(rx, tx, clientPk.getAsBytes(), clientSk.getAsBytes(), serverPk.getAsBytes())) {
            throw new SodiumException("Failed creating client session keys.");
        }

        return new SessionPair(rx, tx);
    }

    @Override
    @Deprecated(forRemoval = true, since = "6.0.0")
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    public SessionPair cryptoKxServerSessionKeys(KeyPair serverKeyPair, KeyPair clientKeyPair) throws SodiumException {
        return cryptoKxServerSessionKeys(serverKeyPair.getPublicKey(), serverKeyPair.getSecretKey(), clientKeyPair.getPublicKey());
    }

    @Override
    public SessionPair cryptoKxServerSessionKeys(KeyPair serverKeyPair, Key clientPublicKey) throws SodiumException {
        return cryptoKxServerSessionKeys(serverKeyPair.getPublicKey(), serverKeyPair.getSecretKey(), clientPublicKey);
    }


    //// -------------------------------------------|
    //// PASSWORD HASHING
    //// -------------------------------------------|

    @Override
    public boolean cryptoPwHash(byte[] outputHash,
                                int outputHashLen,
                                byte[] password,
                                int passwordLen,
                                byte[] salt,
                                long opsLimit,
                                NativeLong memLimit,
                                PwHash.Alg alg) {
        BaseChecker.checkArrayLength("outputHash", outputHash, outputHashLen);
        PwHash.Checker.checkLengthOfHash(outputHashLen);
        BaseChecker.checkArrayLength("password", password, passwordLen);
        PwHash.Checker.checkLengthOfPassword(passwordLen);
        PwHash.Checker.checkSalt(salt);
        PwHash.Checker.checkOpsLimit(opsLimit);
        PwHash.Checker.checkMemLimit(memLimit);

        int res = getSodium().crypto_pwhash(outputHash,
                outputHashLen,
                password,
                passwordLen,
                salt,
                opsLimit,
                memLimit,
                alg.getValue());
        return successful(res);
    }

    @Override
    public boolean cryptoPwHashStr(byte[] outputStr,
                                   byte[] password,
                                   int passwordLen,
                                   long opsLimit,
                                   NativeLong memLimit) {
        PwHash.Checker.checkHashStrOutput(outputStr);
        BaseChecker.checkArrayLength("password", password, passwordLen);
        PwHash.Checker.checkLengthOfPassword(passwordLen);
        PwHash.Checker.checkOpsLimit(opsLimit);
        PwHash.Checker.checkMemLimit(memLimit);

        int res = getSodium().crypto_pwhash_str(outputStr, password, passwordLen, opsLimit, memLimit);
        return successful(res);
    }

    @Override
    public boolean cryptoPwHashStrVerify(byte[] hash, byte[] password, int passwordLen) {
        PwHash.Checker.checkHashStrInput(hash);
        BaseChecker.checkArrayLength("password", password, passwordLen);
        return successful(getSodium().crypto_pwhash_str_verify(hash, password, passwordLen));
    }

    @Override
    public PwHash.NeedsRehashResult cryptoPwHashStrNeedsRehash(byte[] hash, long opsLimit, NativeLong memLimit) {
        PwHash.Checker.checkHashStrInput(hash);
        PwHash.Checker.checkOpsLimit(opsLimit);
        PwHash.Checker.checkMemLimit(memLimit);
        return PwHash.NeedsRehashResult.valueOf(getSodium().crypto_pwhash_str_needs_rehash(hash, opsLimit, memLimit));
    }


    // lazy

    @Override
    public String cryptoPwHash(String password, int lengthOfHash, byte[] salt, long opsLimit, NativeLong memLimit, PwHash.Alg alg)
            throws SodiumException {
        byte[] passwordBytes = bytes(password);
        PwHash.Checker.checkPassword(passwordBytes);
        PwHash.Checker.checkLengthOfHash(lengthOfHash);
        PwHash.Checker.checkSalt(salt);
        PwHash.Checker.checkOpsLimit(opsLimit);
        PwHash.Checker.checkMemLimit(memLimit);
        byte[] hash = new byte[lengthOfHash];
        int res = getSodium().crypto_pwhash(hash, hash.length, passwordBytes, passwordBytes.length, salt, opsLimit, memLimit, alg.getValue());
        if (res != 0) {
            throw new SodiumException(
                    "Could not hash your string. This may be due to insufficient " +
                            "memory or your CPU does not support Argon2's instruction set."
            );
        }
        return messageEncoder.encode(hash);
    }

    @Override
    public String cryptoPwHashString(String password, long opsLimit, NativeLong memLimit) throws SodiumException {
        byte[] hash = new byte[PwHash.STR_BYTES];
        byte[] passwordBytes = bytes(password);
        PwHash.Checker.checkPassword(passwordBytes);
        PwHash.Checker.checkOpsLimit(opsLimit);
        PwHash.Checker.checkMemLimit(memLimit);
        boolean res = cryptoPwHashStr(hash, passwordBytes, passwordBytes.length, opsLimit, memLimit);
        if (!res) {
            throw new SodiumException("Password hashing failed.");
        }
        return decodeAsciiz(hash);
    }

    @Override
    @Deprecated
    public String cryptoPwHashStr(String password, long opsLimit, NativeLong memLimit) throws SodiumException {
        byte[] hash = new byte[PwHash.STR_BYTES];
        byte[] passwordBytes = bytes(password);
        PwHash.Checker.checkPassword(passwordBytes);
        PwHash.Checker.checkOpsLimit(opsLimit);
        PwHash.Checker.checkMemLimit(memLimit);
        boolean res = cryptoPwHashStr(hash, passwordBytes, passwordBytes.length, opsLimit, memLimit);
        if (!res) {
            throw new SodiumException("Password hashing failed.");
        }
        return messageEncoder.encode(hash);
    }

    @Override
    @Deprecated
    public String cryptoPwHashStrRemoveNulls(String password, long opsLimit, NativeLong memLimit) throws SodiumException {
        byte[] hash = new byte[PwHash.STR_BYTES];
        byte[] passwordBytes = bytes(password);
        boolean res = cryptoPwHashStr(hash, passwordBytes, passwordBytes.length, opsLimit, memLimit);
        if (!res) {
            throw new SodiumException("Password hashing failed.");
        }

        byte[] hashNoNulls = removeNulls(hash);
        return messageEncoder.encode(hashNoNulls);
    }

    @Override
    public boolean cryptoPwHashStringVerify(String hash, String password) {
        byte[] hashBytes = encodeToAsciiz(hash);
        byte[] passwordBytes = bytes(password);

        return cryptoPwHashStrVerify(hashBytes, passwordBytes, passwordBytes.length);
    }

    @Override
    @Deprecated
    public boolean cryptoPwHashStrVerify(String hash, String password) {
        byte[] hashBytes = messageEncoder.decode(hash);
        byte[] passwordBytes = bytes(password);

        // If the end of the hash does not have an null byte,
        // let's add it.
        byte endOfHash = hashBytes[hashBytes.length - 1];

        if (endOfHash != 0) {
            byte[] hashWithNullByte = new byte[hashBytes.length + 1];
            System.arraycopy(hashBytes, 0, hashWithNullByte, 0, hashBytes.length);
            hashBytes = hashWithNullByte;
        }


        return cryptoPwHashStrVerify(hashBytes, passwordBytes, passwordBytes.length);
    }

    @Override
    public PwHash.NeedsRehashResult cryptoPwHashStringNeedsRehash(String hash, long opsLimit, NativeLong memLimit) {
        byte[] hashBytes = encodeToAsciiz(hash);

        return cryptoPwHashStrNeedsRehash(hashBytes, opsLimit, memLimit);
    }


    //// -------------------------------------------|
    //// HASH
    //// -------------------------------------------|


    @Override
    public boolean cryptoHashSha256(byte[] out, byte[] in, int inLen) {
        Hash.Checker.checkHashSha256(out);
        BaseChecker.checkArrayLength("in", in, inLen);
        return successful(getSodium().crypto_hash_sha256(out, in, inLen));
    }

    @Override
    public boolean cryptoHashSha256Init(Hash.State256 state) {
        BaseChecker.requireNonNull("state", state);
        return successful(getSodium().crypto_hash_sha256_init(state));
    }

    @Override
    public boolean cryptoHashSha256Update(Hash.State256 state, byte[] in, int inLen) {
        BaseChecker.requireNonNull("state", state);
        BaseChecker.checkArrayLength("in", in, inLen);
        return successful(getSodium().crypto_hash_sha256_update(state, in, inLen));
    }

    @Override
    public boolean cryptoHashSha256Final(Hash.State256 state, byte[] out) {
        BaseChecker.requireNonNull("state", state);
        Hash.Checker.checkHashSha256(out);
        return successful(getSodium().crypto_hash_sha256_final(state, out));
    }

    @Override
    public boolean cryptoHashSha512(byte[] out, byte[] in, int inLen) {
        Hash.Checker.checkHashSha512(out);
        BaseChecker.checkArrayLength("in", in, inLen);
        return successful(getSodium().crypto_hash_sha512(out, in, inLen));
    }

    @Override
    public boolean cryptoHashSha512Init(Hash.State512 state) {
        BaseChecker.requireNonNull("state", state);
        return successful(getSodium().crypto_hash_sha512_init(state));
    }

    @Override
    public boolean cryptoHashSha512Update(Hash.State512 state, byte[] in, int inLen) {
        BaseChecker.requireNonNull("state", state);
        BaseChecker.checkArrayLength("in", in, inLen);
        return successful(getSodium().crypto_hash_sha512_update(state, in, inLen));
    }

    @Override
    public boolean cryptoHashSha512Final(Hash.State512 state, byte[] out) {
        BaseChecker.requireNonNull("state", state);
        Hash.Checker.checkHashSha512(out);
        return successful(getSodium().crypto_hash_sha512_final(state, out));
    }

    // -- lazy


    @Override
    public String cryptoHashSha256(String message) throws SodiumException {
        byte[] msgBytes = bytes(message);
        byte[] hashedBytes = new byte[Hash.SHA256_BYTES];
        if (!cryptoHashSha256(hashedBytes, msgBytes, msgBytes.length)) {
            throw new SodiumException("Unsuccessful sha-256 hash.");
        }
        return messageEncoder.encode(hashedBytes);
    }

    @Override
    public String cryptoHashSha512(String message) throws SodiumException {
        byte[] msgBytes = bytes(message);
        byte[] hashedBytes = new byte[Hash.SHA512_BYTES];
        if (!cryptoHashSha512(hashedBytes, msgBytes, msgBytes.length)) {
            throw new SodiumException("Unsuccessful sha-512 hash.");
        }
        return messageEncoder.encode(hashedBytes);
    }


    @Override
    public boolean cryptoHashSha256Update(Hash.State256 state, String messagePart) {
        byte[] msgBytes = bytes(messagePart);
        return cryptoHashSha256Update(state, msgBytes, msgBytes.length);
    }

    @Override
    public String cryptoHashSha256Final(Hash.State256 state) throws SodiumException {
        byte[] finalHash = new byte[Hash.SHA256_BYTES];
        if (!cryptoHashSha256Final(state, finalHash)) {
            throw new SodiumException("Could not finalise sha-256.");
        }
        return messageEncoder.encode(finalHash);
    }


    @Override
    public boolean cryptoHashSha512Update(Hash.State512 state, String messagePart) {
        byte[] msgBytes = bytes(messagePart);
        return cryptoHashSha512Update(state, msgBytes, msgBytes.length);
    }

    @Override
    public String cryptoHashSha512Final(Hash.State512 state) throws SodiumException {
        byte[] finalHash = new byte[Hash.SHA512_BYTES];
        if (!cryptoHashSha512Final(state, finalHash)) {
            throw new SodiumException("Could not finalise sha-512.");
        }
        return messageEncoder.encode(finalHash);
    }


    //// -------------------------------------------|
    //// SECRET BOX
    //// -------------------------------------------|

    @Override
    public void cryptoSecretBoxKeygen(byte[] key) {
        SecretBox.Checker.checkKey(key);

        getSodium().crypto_secretbox_keygen(key);
    }

    @Override
    public boolean cryptoSecretBoxEasy(byte[] cipherText, byte[] message, int messageLen, byte[] nonce, byte[] key) {
        BaseChecker.checkArrayLength("message", message, messageLen);
        SecretBox.Checker.checkCipherText(cipherText, messageLen);
        SecretBox.Checker.checkNonce(nonce);
        SecretBox.Checker.checkKey(key);

        return successful(getSodium().crypto_secretbox_easy(cipherText, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoSecretBoxOpenEasy(byte[] message, byte[] cipherText, int cipherTextLen, byte[] nonce, byte[] key) {
        BaseChecker.checkArrayLength("cipherText", cipherText, cipherTextLen);
        SecretBox.Checker.checkCipherTextLength(cipherTextLen);
        SecretBox.Checker.checkMessage(message, cipherTextLen);
        SecretBox.Checker.checkNonce(nonce);
        SecretBox.Checker.checkKey(key);

        return successful(getSodium().crypto_secretbox_open_easy(message, cipherText, cipherTextLen, nonce, key));
    }

    @Override
    public boolean cryptoSecretBoxDetached(byte[] cipherText, byte[] mac, byte[] message, int messageLen, byte[] nonce, byte[] key) {
        BaseChecker.checkArrayLength("message", message, messageLen);
        BaseChecker.checkExpectedMemorySize("cipherText length", cipherText.length, messageLen);
        SecretBox.Checker.checkMac(mac);
        SecretBox.Checker.checkNonce(nonce);
        SecretBox.Checker.checkKey(key);

        return successful(getSodium().crypto_secretbox_detached(cipherText, mac, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoSecretBoxOpenDetached(byte[] message, byte[] cipherText, byte[] mac, int cipherTextLen, byte[] nonce, byte[] key) {
        BaseChecker.checkArrayLength("cipherText", cipherText, cipherTextLen);
        BaseChecker.checkExpectedMemorySize("message length", message.length, cipherTextLen);
        SecretBox.Checker.checkMac(mac);
        SecretBox.Checker.checkNonce(nonce);
        SecretBox.Checker.checkKey(key);

        return successful(getSodium().crypto_secretbox_open_detached(message, cipherText, mac, cipherTextLen, nonce, key));
    }


    /// --- Lazy

    @Override
    public Key cryptoSecretBoxKeygen() {
        byte[] key = new byte[SecretBox.KEYBYTES];
        cryptoSecretBoxKeygen(key);
        return Key.fromBytes(key);
    }

    @Override
    public String cryptoSecretBoxEasy(String message, byte[] nonce, Key key) throws SodiumException {
        byte[] keyBytes = key.getAsBytes();
        byte[] messageBytes = bytes(message);
        byte[] cipherTextBytes = new byte[SecretBox.MACBYTES + messageBytes.length];

        if (!cryptoSecretBoxEasy(cipherTextBytes, messageBytes, messageBytes.length, nonce, keyBytes)) {
            throw new SodiumException("Could not encrypt message.");
        }

        return messageEncoder.encode(cipherTextBytes);
    }

    @Override
    public String cryptoSecretBoxOpenEasy(String cipher, byte[] nonce, Key key) throws SodiumException {
        byte[] keyBytes = key.getAsBytes();
        byte[] cipherBytes = messageEncoder.decode(cipher);
        SecretBox.Checker.checkCipherTextLength(cipherBytes.length);
        byte[] messageBytes = new byte[cipherBytes.length - SecretBox.MACBYTES];

        if (!cryptoSecretBoxOpenEasy(messageBytes, cipherBytes, cipherBytes.length, nonce, keyBytes)) {
            throw new SodiumException("Could not decrypt message.");
        }

        return str(messageBytes);
    }

    @Override
    public DetachedEncrypt cryptoSecretBoxDetached(String message, byte[] nonce, Key key) throws SodiumException {
        byte[] keyBytes = key.getAsBytes();
        byte[] messageBytes = bytes(message);
        byte[] cipherTextBytes = new byte[messageBytes.length];
        byte[] macBytes = new byte[SecretBox.MACBYTES];

        if (!cryptoSecretBoxDetached(cipherTextBytes, macBytes, messageBytes, messageBytes.length, nonce, keyBytes)) {
            throw new SodiumException("Could not encrypt detached message.");
        }

        return new DetachedEncrypt(cipherTextBytes, macBytes);
    }

    @Override
    public String cryptoSecretBoxOpenDetached(DetachedEncrypt cipherAndMac, byte[] nonce, Key key) throws SodiumException {
        byte[] keyBytes = key.getAsBytes();
        byte[] cipherBytes = cipherAndMac.getCipher();
        byte[] macBytes = cipherAndMac.getMac();
        byte[] messageBytes = new byte[cipherBytes.length];

        if (!cryptoSecretBoxOpenDetached(messageBytes, cipherBytes, macBytes, cipherBytes.length, nonce, keyBytes)) {
            throw new SodiumException("Could not decrypt detached message.");
        }

        return str(messageBytes);
    }


    //// -------------------------------------------|
    //// DIFFIE HELLMAN
    //// -------------------------------------------|

    @Override
    public boolean cryptoScalarMultBase(byte[] publicKey, byte[] secretKey) {
        DiffieHellman.Checker.checkPublicKey(publicKey);
        DiffieHellman.Checker.checkSecretKey(secretKey);
        return successful(getSodium().crypto_scalarmult_base(publicKey, secretKey));
    }

    @Override
    public Key cryptoScalarMultBase(Key secretKey) {
        byte[] publicKey = new byte[DiffieHellman.SCALARMULT_BYTES];
        cryptoScalarMultBase(publicKey, secretKey.getAsBytes());
        return Key.fromBytes(publicKey);
    }

    @Override
    public boolean cryptoScalarMult(byte[] shared, byte[] secretKey, byte[] publicKey) {
        DiffieHellman.Checker.checkSharedKey(shared);
        DiffieHellman.Checker.checkPublicKey(publicKey);
        DiffieHellman.Checker.checkSecretKey(secretKey);
        return successful(getSodium().crypto_scalarmult(shared, secretKey, publicKey));
    }

    @Override
    public Key cryptoScalarMult(Key secretKey, Key publicKey) {
        byte[] sharedKey = new byte[DiffieHellman.SCALARMULT_BYTES];
        cryptoScalarMult(sharedKey, secretKey.getAsBytes(), publicKey.getAsBytes());
        return Key.fromBytes(sharedKey);
    }


    //// -------------------------------------------|
    //// CRYPTO BOX
    //// -------------------------------------------|

    @Override
    public boolean cryptoBoxKeypair(byte[] publicKey, byte[] secretKey) {
        Box.Checker.checkPublicKey(publicKey);
        Box.Checker.checkSecretKey(secretKey);
        return successful(getSodium().crypto_box_keypair(publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed) {
        Box.Checker.checkPublicKey(publicKey);
        Box.Checker.checkSecretKey(secretKey);
        Box.Checker.checkSeed(seed);
        return successful(getSodium().crypto_box_seed_keypair(publicKey, secretKey, seed));
    }

    @Override
    public boolean cryptoBoxEasy(byte[] cipherText, byte[] message, int messageLen, byte[] nonce, byte[] publicKey, byte[] secretKey) {
        BaseChecker.checkArrayLength("message", message, messageLen);
        Box.Checker.checkCipherText(cipherText, messageLen);
        Box.Checker.checkNonce(nonce);
        Box.Checker.checkPublicKey(publicKey);
        Box.Checker.checkSecretKey(secretKey);
        return successful(getSodium().crypto_box_easy(cipherText, message, messageLen, nonce, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxOpenEasy(byte[] message, byte[] cipherText, int cipherTextLen, byte[] nonce, byte[] publicKey, byte[] secretKey) {
        BaseChecker.checkArrayLength("cipherText", cipherText, cipherTextLen);
        Box.Checker.checkCipherTextLength(cipherTextLen);
        Box.Checker.checkMessage(message, cipherTextLen);
        Box.Checker.checkNonce(nonce);
        Box.Checker.checkPublicKey(publicKey);
        Box.Checker.checkSecretKey(secretKey);
        return successful(getSodium().crypto_box_open_easy(message, cipherText, cipherTextLen, nonce, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxDetached(byte[] cipherText, byte[] mac, byte[] message, int messageLen, byte[] nonce, byte[] publicKey, byte[] secretKey) {
        BaseChecker.checkArrayLength("message", message, messageLen);
        BaseChecker.checkExpectedMemorySize("cipherText length", cipherText.length, messageLen);
        Box.Checker.checkMac(mac);
        Box.Checker.checkNonce(nonce);
        Box.Checker.checkPublicKey(publicKey);
        Box.Checker.checkSecretKey(secretKey);
        return successful(getSodium().crypto_box_detached(cipherText, mac, message, messageLen, nonce, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxOpenDetached(byte[] message, byte[] cipherText, byte[] mac, int cipherTextLen, byte[] nonce, byte[] publicKey, byte[] secretKey) {
        BaseChecker.checkArrayLength("cipherText", cipherText, cipherTextLen);
        BaseChecker.checkExpectedMemorySize("message length", message.length, cipherTextLen);
        Box.Checker.checkMac(mac);
        Box.Checker.checkNonce(nonce);
        Box.Checker.checkPublicKey(publicKey);
        Box.Checker.checkSecretKey(secretKey);
        return successful(getSodium().crypto_box_open_detached(message, cipherText, mac, cipherTextLen, nonce, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxBeforeNm(byte[] k, byte[] publicKey, byte[] secretKey) {
        Box.Checker.checkSharedKey(k);
        Box.Checker.checkPublicKey(publicKey);
        Box.Checker.checkSecretKey(secretKey);
        return successful(getSodium().crypto_box_beforenm(k, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxEasyAfterNm(byte[] cipherText, byte[] message, int messageLen, byte[] nonce, byte[] key) {
        BaseChecker.checkArrayLength("message", message, messageLen);
        Box.Checker.checkCipherText(cipherText, messageLen);
        Box.Checker.checkNonce(nonce);
        Box.Checker.checkSharedKey(key);
        return successful(getSodium().crypto_box_easy_afternm(cipherText, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoBoxOpenEasyAfterNm(byte[] message, byte[] cipherText, int cipherTextLen, byte[] nonce, byte[] key) {
        BaseChecker.checkArrayLength("cipherText", cipherText, cipherTextLen);
        Box.Checker.checkCipherTextLength(cipherTextLen);
        Box.Checker.checkMessage(message, cipherTextLen);
        Box.Checker.checkNonce(nonce);
        Box.Checker.checkSharedKey(key);
        return successful(getSodium().crypto_box_open_easy_afternm(message, cipherText, cipherTextLen, nonce, key));
    }

    @Override
    public boolean cryptoBoxDetachedAfterNm(byte[] cipherText, byte[] mac, byte[] message, int messageLen, byte[] nonce, byte[] key) {
        BaseChecker.checkArrayLength("message", message, messageLen);
        BaseChecker.checkExpectedMemorySize("cipherText length", cipherText.length, messageLen);
        Box.Checker.checkMac(mac);
        Box.Checker.checkNonce(nonce);
        Box.Checker.checkSharedKey(key);
        return successful(getSodium().crypto_box_detached_afternm(cipherText, mac, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoBoxOpenDetachedAfterNm(byte[] message, byte[] cipherText, byte[] mac, int cipherTextLen, byte[] nonce, byte[] key) {
        BaseChecker.checkArrayLength("cipherText", cipherText, cipherTextLen);
        BaseChecker.checkExpectedMemorySize("message length", message.length, cipherTextLen);
        Box.Checker.checkMac(mac);
        Box.Checker.checkNonce(nonce);
        Box.Checker.checkSharedKey(key);
        return successful(getSodium().crypto_box_open_detached_afternm(message, cipherText, mac, cipherTextLen, nonce, key));
    }

    @Override
    public boolean cryptoBoxSeal(byte[] cipher, byte[] message, int messageLen, byte[] publicKey) {
        BaseChecker.checkArrayLength("message", message, messageLen);
        Box.Checker.checkSealCipherText(cipher, messageLen);
        Box.Checker.checkPublicKey(publicKey);
        return successful(getSodium().crypto_box_seal(cipher, message, messageLen, publicKey));
    }

    @Override
    public boolean cryptoBoxSealOpen(byte[] message, byte[] cipher, int cipherLen, byte[] publicKey, byte[] secretKey) {
        BaseChecker.checkArrayLength("cipher", cipher, cipherLen);
        Box.Checker.checkSealCipherTextLength(cipherLen);
        Box.Checker.checkSealMessage(message, cipherLen);
        Box.Checker.checkPublicKey(publicKey);
        Box.Checker.checkSecretKey(secretKey);
        return successful(getSodium().crypto_box_seal_open(message, cipher, cipherLen, publicKey, secretKey));
    }

    // -- lazy

    @Override
    public KeyPair cryptoBoxKeypair() throws SodiumException {
        byte[] publicKey = randomBytesBuf(Box.PUBLICKEYBYTES);
        byte[] secretKey = randomBytesBuf(Box.SECRETKEYBYTES);
        if (!cryptoBoxKeypair(publicKey, secretKey)) {
            throw new SodiumException("Unable to create a public and private key.");
        }
        return new KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secretKey));
    }

    @Override
    public KeyPair cryptoBoxSeedKeypair(byte[] seed) throws SodiumException {
        byte[] publicKey = randomBytesBuf(Box.PUBLICKEYBYTES);
        byte[] secretKey = randomBytesBuf(Box.SECRETKEYBYTES);
        if (!cryptoBoxSeedKeypair(publicKey, secretKey, seed)) {
            throw new SodiumException("Unable to create a public and private key.");
        }
        return new KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secretKey));
    }

    @Override
    public String cryptoBoxEasy(String message, byte[] nonce, KeyPair keyPair) throws SodiumException {
        byte[] messageBytes = bytes(message);
        byte[] cipherBytes = new byte[Box.MACBYTES + messageBytes.length];
        boolean res = cryptoBoxEasy(
                cipherBytes,
                messageBytes,
                messageBytes.length,
                nonce,
                keyPair.getPublicKey().getAsBytes(),
                keyPair.getSecretKey().getAsBytes()
        );
        if (!res) {
            throw new SodiumException("Could not encrypt your message.");
        }
        return messageEncoder.encode(cipherBytes);
    }

    @Override
    public String cryptoBoxOpenEasy(String cipherText, byte[] nonce, KeyPair keyPair) throws SodiumException {
        byte[] cipher = messageEncoder.decode(cipherText);
        Box.Checker.checkCipherTextLength(cipher.length);
        byte[] message = new byte[cipher.length - Box.MACBYTES];
        boolean res =
                cryptoBoxOpenEasy(
                        message,
                        cipher,
                        cipher.length,
                        nonce,
                        keyPair.getPublicKey().getAsBytes(),
                        keyPair.getSecretKey().getAsBytes()
                );

        if (!res) {
            throw new SodiumException("Could not decrypt your message.");
        }

        return str(message);
    }

    @Override
    public String cryptoBoxBeforeNm(byte[] publicKey, byte[] secretKey) throws SodiumException {
        byte[] sharedKey = new byte[Box.BEFORENMBYTES];
        boolean res = cryptoBoxBeforeNm(sharedKey, publicKey, secretKey);
        if (!res) {
            throw new SodiumException("Unable to generate shared secret key.");
        }
        return messageEncoder.encode(sharedKey);
    }

    @Override
    public String cryptoBoxBeforeNm(KeyPair keyPair) throws SodiumException {
        return cryptoBoxBeforeNm(keyPair.getPublicKey().getAsBytes(), keyPair.getSecretKey().getAsBytes());
    }

    @Override
    public String cryptoBoxEasyAfterNm(String message, byte[] nonce, String sharedSecretKey) throws SodiumException {
        byte[] sharedKey = messageEncoder.decode(sharedSecretKey);
        byte[] messageBytes = bytes(message);
        byte[] cipher = new byte[messageBytes.length + Box.MACBYTES];

        boolean res = cryptoBoxEasyAfterNm(cipher, messageBytes, messageBytes.length, nonce, sharedKey);
        if (!res) {
            throw new SodiumException("Could not fully complete shared secret key encryption.");
        }

        return messageEncoder.encode(cipher);
    }

    @Override
    public String cryptoBoxOpenEasyAfterNm(String cipher, byte[] nonce, String sharedSecretKey) throws SodiumException {
        byte[] sharedKey = messageEncoder.decode(sharedSecretKey);
        byte[] cipherBytes = messageEncoder.decode(cipher);
        Box.Checker.checkCipherTextLength(cipherBytes.length);
        byte[] message = new byte[cipherBytes.length - Box.MACBYTES];

        boolean res = cryptoBoxOpenEasyAfterNm(message, cipherBytes, cipherBytes.length, nonce, sharedKey);
        if (!res) {
            throw new SodiumException("Could not fully complete shared secret key decryption.");
        }

        return str(message);
    }

    @Override
    public DetachedEncrypt cryptoBoxDetachedAfterNm(String message, byte[] nonce, String sharedSecretKey) throws SodiumException {
        byte[] sharedKey = messageEncoder.decode(sharedSecretKey);
        byte[] messageBytes = bytes(message);
        byte[] cipher = new byte[messageBytes.length];
        byte[] mac = new byte[Box.MACBYTES];

        boolean res = cryptoBoxDetachedAfterNm(cipher, mac, messageBytes, messageBytes.length, nonce, sharedKey);
        if (!res) {
            throw new SodiumException("Could not fully complete shared secret key detached encryption.");
        }

        return new DetachedEncrypt(cipher, mac);
    }

    @Override
    public DetachedDecrypt cryptoBoxOpenDetachedAfterNm(DetachedEncrypt detachedEncrypt, byte[] nonce, String sharedSecretKey) throws SodiumException {
        byte[] sharedKey = messageEncoder.decode(sharedSecretKey);
        byte[] cipherBytes = detachedEncrypt.getCipher();
        byte[] mac = detachedEncrypt.getMac();
        byte[] message = new byte[cipherBytes.length];

        boolean res = cryptoBoxOpenDetachedAfterNm(message, cipherBytes, mac, cipherBytes.length, nonce, sharedKey);
        if (!res) {
            throw new SodiumException("Could not fully complete shared secret key detached decryption.");
        }

        return new DetachedDecrypt(message, mac);
    }

    @Override
    public String cryptoBoxSealEasy(String message, Key publicKey) throws SodiumException {
        byte[] keyBytes = publicKey.getAsBytes();
        byte[] messageBytes = bytes(message);
        byte[] cipher = new byte[Box.SEALBYTES + messageBytes.length];

        if (!cryptoBoxSeal(cipher, messageBytes, messageBytes.length, keyBytes)) {
            throw new SodiumException("Could not encrypt message.");
        }
        return messageEncoder.encode(cipher);
    }

    @Override
    public String cryptoBoxSealOpenEasy(String cipherText, KeyPair keyPair) throws SodiumException {
        byte[] cipher = messageEncoder.decode(cipherText);
        Box.Checker.checkCipherTextLength(cipher.length);
        byte[] message = new byte[cipher.length - Box.SEALBYTES];

        boolean res = cryptoBoxSealOpen(message,
                cipher,
                cipher.length,
                keyPair.getPublicKey().getAsBytes(),
                keyPair.getSecretKey().getAsBytes());
        if (!res) {
            throw new SodiumException("Could not decrypt your message.");
        }
        return str(message);
    }

    //// -------------------------------------------|
    //// CRYPTO SIGN
    //// -------------------------------------------|

    @Override
    public boolean cryptoSignInit(Sign.StateCryptoSign state) {
        return successful(getSodium().crypto_sign_init(state));
    }

    @Override
    public boolean cryptoSignUpdate(Sign.StateCryptoSign state, byte[] chunk, int chunkLength) {
        BaseChecker.checkArrayLength("chunk", chunk, chunkLength);
        return successful(getSodium().crypto_sign_update(state, chunk, chunkLength));
    }

    @Override
    public boolean cryptoSignFinalCreate(Sign.StateCryptoSign state, byte[] sig, byte[] sk) {
        Sign.Checker.checkSignature(sig);
        Sign.Checker.checkSecretKey(sk);
        return successful(getSodium().crypto_sign_final_create(state, sig, null, sk));
    }

    @Override
    public boolean cryptoSignFinalVerify(Sign.StateCryptoSign state, byte[] sig, byte[] pk) {
        Sign.Checker.checkSignature(sig);
        Sign.Checker.checkPublicKey(pk);
        return successful(getSodium().crypto_sign_final_verify(state, sig, pk));
    }

    @Override
    public boolean cryptoSignKeypair(byte[] publicKey, byte[] secretKey) {
        Sign.Checker.checkPublicKey(publicKey);
        Sign.Checker.checkSecretKey(secretKey);
        return successful(getSodium().crypto_sign_keypair(publicKey, secretKey));
    }

    @Override
    public boolean cryptoSignSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed) {
        Sign.Checker.checkPublicKey(publicKey);
        Sign.Checker.checkSecretKey(secretKey);
        Sign.Checker.checkSeed(seed);
        return successful(getSodium().crypto_sign_seed_keypair(publicKey, secretKey, seed));
    }

    @Override
    public boolean cryptoSign(byte[] signedMessage, byte[] message, int messageLen, byte[] secretKey) {
        BaseChecker.checkArrayLength("message", message, messageLen);
        Sign.Checker.checkSignedMessageLength(signedMessage, messageLen);
        Sign.Checker.checkSecretKey(secretKey);
        return successful(getSodium().crypto_sign(signedMessage, (new PointerByReference(Pointer.NULL)).getPointer(), message, messageLen, secretKey));
    }

    @Override
    public boolean cryptoSignOpen(byte[] message, byte[] signedMessage, int signedMessageLen, byte[] publicKey) {
        BaseChecker.checkArrayLength("signedMessage", signedMessage, signedMessageLen);
        Sign.Checker.checkMessageLength(message, signedMessageLen);
        Sign.Checker.checkPublicKey(publicKey);
        return successful(getSodium().crypto_sign_open(message, (new PointerByReference(Pointer.NULL)).getPointer(), signedMessage, signedMessageLen, publicKey));
    }

    @Override
    public boolean cryptoSignDetached(byte[] signature, byte[] message, int messageLen, byte[] secretKey) {
        Sign.Checker.checkSignature(signature);
        BaseChecker.checkArrayLength("message", message, messageLen);
        Sign.Checker.checkSecretKey(secretKey);
        return successful(getSodium().crypto_sign_detached(signature, (new PointerByReference(Pointer.NULL)).getPointer(), message, messageLen, secretKey));
    }

    @Override
    public boolean cryptoSignVerifyDetached(byte[] signature, byte[] message, int messageLen, byte[] publicKey) {
        Sign.Checker.checkSignature(signature);
        BaseChecker.checkArrayLength("message", message, messageLen);
        Sign.Checker.checkPublicKey(publicKey);
        return successful(getSodium().crypto_sign_verify_detached(signature, message, messageLen, publicKey));
    }

    @Override
    public boolean convertPublicKeyEd25519ToCurve25519(byte[] curve, byte[] ed) {
        Sign.Checker.checkPublicKeyCurve25519(curve);
        Sign.Checker.checkPublicKeyEd25519(ed);
        return successful(getSodium().crypto_sign_ed25519_pk_to_curve25519(curve, ed));
    }

    @Override
    public boolean convertSecretKeyEd25519ToCurve25519(byte[] curve, byte[] ed) {
        Sign.Checker.checkSecretKeyCurve25519(curve);
        Sign.Checker.checkSecretKeyEd25519(ed);
        return successful(getSodium().crypto_sign_ed25519_sk_to_curve25519(curve, ed));
    }

    @Override
    public boolean cryptoSignEd25519SkToSeed(byte[] seed, byte[] ed) {
        Sign.Checker.checkSeed(seed);
        Sign.Checker.checkSecretKeyEd25519(ed);
        return successful(getSodium().crypto_sign_ed25519_sk_to_seed(seed, ed));
    }

    @Override
    public boolean cryptoSignEd25519SkToPk(byte[] publicKey, byte[] secretKey) {
        Sign.Checker.checkPublicKey(publicKey);
        Sign.Checker.checkSecretKey(secretKey);
        return successful(getSodium().crypto_sign_ed25519_sk_to_pk(publicKey, secretKey));
    }

    // -- lazy

    @Override
    public KeyPair cryptoSignKeypair() throws SodiumException {
        byte[] publicKey = new byte[Sign.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Sign.SECRETKEYBYTES];
        if (!cryptoSignKeypair(publicKey, secretKey)) {
            throw new SodiumException("Could not generate a signing keypair.");
        }
        return new KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secretKey));
    }

    @Override
    public KeyPair cryptoSignSeedKeypair(byte[] seed) throws SodiumException {
        byte[] publicKey = new byte[Sign.PUBLICKEYBYTES];
        byte[] secretKey = new byte[Sign.SECRETKEYBYTES];
        if (!cryptoSignSeedKeypair(publicKey, secretKey, seed)) {
            throw new SodiumException("Could not generate a signing keypair with a seed.");
        }
        return new KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secretKey));
    }

    @Override
    public KeyPair cryptoSignSecretKeyPair(Key secretKey) throws SodiumException {
        byte[] publicKey = new byte[Sign.PUBLICKEYBYTES];
        byte[] secKeyBytes = secretKey.getAsBytes();
        if (!cryptoSignEd25519SkToPk(publicKey, secKeyBytes)) {
            throw new SodiumException("Could not extract public key.");
        }
        return new KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secKeyBytes));
    }

    @Override
    public String cryptoSign(String message, String secretKey) throws SodiumException {
        byte[] messageBytes = bytes(message);
        byte[] secretKeyBytes = messageEncoder.decode(secretKey);
        byte[] signedMessage = new byte[Sign.BYTES + messageBytes.length];
        boolean res = cryptoSign(signedMessage, messageBytes, messageBytes.length, secretKeyBytes);

        if (!res) {
            throw new SodiumException("Could not sign your message.");
        }

        return messageEncoder.encode(signedMessage);
    }

    @Override
    public String cryptoSign(String message, Key secretKey) throws SodiumException {
        return cryptoSign(message, messageEncoder.encode(secretKey.getAsBytes()));
    }

    @Override
    public String cryptoSignOpen(String signedMessage, Key publicKey) {
        byte[] signedMessageBytes = messageEncoder.decode(signedMessage);
        Sign.Checker.checkSignedMessageLength(signedMessageBytes.length);
        byte[] messageBytes = new byte[signedMessageBytes.length - Sign.BYTES];
        byte[] publicKeyBytes = publicKey.getAsBytes();

        boolean res = cryptoSignOpen(
                messageBytes,
                signedMessageBytes,
                signedMessageBytes.length,
                publicKeyBytes
        );

        if (!res) {
            return null;
        }

        return str(messageBytes);
    }

    @Override
    public String cryptoSignDetached(String message, Key secretKey) throws SodiumException {
        byte[] messageBytes = bytes(message);
        byte[] skBytes = secretKey.getAsBytes();
        byte[] signatureBytes = new byte[Sign.BYTES];

        if (!cryptoSignDetached(signatureBytes, messageBytes, messageBytes.length, skBytes)) {
            throw new SodiumException("Could not create a signature for your message in detached mode.");
        }

        return messageEncoder.encode(signatureBytes);
    }

    @Override
    public boolean cryptoSignVerifyDetached(String signature, String message, Key publicKey) {
        byte[] messageBytes = bytes(message);
        byte[] pkBytes = publicKey.getAsBytes();
        byte[] signatureBytes = messageEncoder.decode(signature);

        return cryptoSignVerifyDetached(signatureBytes, messageBytes, messageBytes.length, pkBytes);
    }

    @Override
    public KeyPair convertKeyPairEd25519ToCurve25519(KeyPair ed25519KeyPair) throws SodiumException {
        byte[] edPkBytes = ed25519KeyPair.getPublicKey().getAsBytes();
        byte[] edSkBytes = ed25519KeyPair.getSecretKey().getAsBytes();

        byte[] curvePkBytes = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        byte[] curveSkBytes = new byte[Sign.CURVE25519_SECRETKEYBYTES];

        boolean pkSuccess = convertPublicKeyEd25519ToCurve25519(curvePkBytes, edPkBytes);
        boolean skSuccess = convertSecretKeyEd25519ToCurve25519(curveSkBytes, edSkBytes);

        if (!pkSuccess || !skSuccess) {
            throw new SodiumException("Could not convert this key pair.");
        }

        return new KeyPair(Key.fromBytes(curvePkBytes), Key.fromBytes(curveSkBytes));
    }

    @Override
    public byte[] cryptoSignEd25519SkToSeed(Key secretKey) throws SodiumException {
        byte[] seed = new byte[Sign.SEEDBYTES];
        boolean res = cryptoSignEd25519SkToSeed(seed, secretKey.getAsBytes());
        if (!res) {
            throw new SodiumException("Could not convert this secret key.");
        }

        return seed;
    }


    //// -------------------------------------------|
    //// SECRET STREAM
    //// -------------------------------------------|

    @Override
    public void cryptoSecretStreamKeygen(byte[] key) {
        SecretStream.Checker.checkKey(key);
        getSodium().crypto_secretstream_xchacha20poly1305_keygen(key);
    }

    @Override
    public boolean cryptoSecretStreamInitPush(SecretStream.State state, byte[] header, byte[] key) {
        BaseChecker.requireNonNull("state", state);
        SecretStream.Checker.checkHeader(header);
        SecretStream.Checker.checkKey(key);
        return successful(getSodium().crypto_secretstream_xchacha20poly1305_init_push(state, header, key));
    }

    @Override
    public boolean cryptoSecretStreamPush(SecretStream.State state, byte[] cipher, long[] cipherLen, byte[] message, int messageLen, byte tag) {
        BaseChecker.requireNonNull("state", state);
        SecretStream.Checker.checkPush(message, messageLen, cipher);
        BaseChecker.checkOptionalOutPointer("cipherLen", cipherLen);
        return successful(getSodium().crypto_secretstream_xchacha20poly1305_push(
                state,
                cipher,
                cipherLen,
                message,
                messageLen,
                null,
                0L,
                tag
        ));
    }

    @Override
    public boolean cryptoSecretStreamPush(SecretStream.State state,
                                          byte[] cipher,
                                          byte[] message,
                                          int messageLen,
                                          byte tag) {
        BaseChecker.requireNonNull("state", state);
        SecretStream.Checker.checkPush(message, messageLen, cipher);
        return successful(getSodium().crypto_secretstream_xchacha20poly1305_push(
                state,
                cipher,
                null,
                message,
                messageLen,
                null,
                0L,
                tag
        ));
    }

    @Override
    public boolean cryptoSecretStreamPush(SecretStream.State state,
                                          byte[] cipher,
                                          long[] cipherLen,
                                          byte[] message,
                                          int messageLen,
                                          byte[] additionalData,
                                          int additionalDataLen,
                                          byte tag) {
        BaseChecker.requireNonNull("state", state);
        SecretStream.Checker.checkPush(message, messageLen, cipher);
        BaseChecker.checkOptionalOutPointer("cipherLen", cipherLen);
        BaseChecker.checkOptionalArrayLength("additional data", additionalData, additionalDataLen);
        return successful(getSodium().crypto_secretstream_xchacha20poly1305_push(
                state,
                cipher,
                cipherLen,
                message,
                messageLen,
                additionalData,
                additionalDataLen,
                tag
        ));
    }

    @Override
    public boolean cryptoSecretStreamInitPull(SecretStream.State state, byte[] header, byte[] key) {
        BaseChecker.requireNonNull("state", state);
        SecretStream.Checker.checkHeader(header);
        SecretStream.Checker.checkKey(key);
        return successful(getSodium().crypto_secretstream_xchacha20poly1305_init_pull(state, header, key));
    }

    @Override
    public boolean cryptoSecretStreamPull(SecretStream.State state,
                                          byte[] message,
                                          long[] messageLen,
                                          byte[] tag,
                                          byte[] cipher,
                                          int cipherLen,
                                          byte[] additionalData,
                                          int additionalDataLen) {
        BaseChecker.requireNonNull("state", state);
        SecretStream.Checker.checkPull(cipher, cipherLen, message);
        BaseChecker.checkOptionalOutPointer("messageLen", messageLen);
        BaseChecker.checkOptionalOutPointer("tag", tag);
        BaseChecker.checkOptionalArrayLength("additional data", additionalData, additionalDataLen);
        return successful(getSodium().crypto_secretstream_xchacha20poly1305_pull(
                state, message, messageLen, tag, cipher, cipherLen, additionalData, additionalDataLen
        ));
    }

    @Override
    public boolean cryptoSecretStreamPull(SecretStream.State state, byte[] message, byte[] tag, byte[] cipher, int cipherLen) {
        BaseChecker.requireNonNull("state", state);
        SecretStream.Checker.checkPull(cipher, cipherLen, message);
        BaseChecker.checkOptionalOutPointer("tag", tag);
        return successful(getSodium().crypto_secretstream_xchacha20poly1305_pull(
                state,
                message,
                null,
                tag,
                cipher,
                cipherLen,
                null,
                0L
        ));
    }

    @Override
    public Key cryptoSecretStreamKeygen() {
        byte[] key = randomBytesBuf(SecretStream.KEYBYTES);
        getSodium().crypto_secretstream_xchacha20poly1305_keygen(key);
        return Key.fromBytes(key);
    }

    @Override
    public SecretStream.State cryptoSecretStreamInitPush(byte[] header, Key key) throws SodiumException {
        SecretStream.Checker.checkHeader(header);
        SecretStream.Checker.checkKey(key.getAsBytes());
        SecretStream.State state = new SecretStream.State.ByReference();
        int res = getSodium().crypto_secretstream_xchacha20poly1305_init_push(state, header, key.getAsBytes());
        if (res != 0) {
            throw new SodiumException("Error initializing secret stream push.");
        }
        return state;
    }

    @Override
    public String cryptoSecretStreamPush(SecretStream.State state, String message, byte tag) throws SodiumException {
        byte[] messageBytes = bytes(message);
        byte[] cipher = new byte[SecretStream.ABYTES + messageBytes.length];
        int res = getSodium().crypto_secretstream_xchacha20poly1305_push(
                state,
                cipher,
                null,
                messageBytes,
                messageBytes.length,
                null,
                0L,
                tag
        );

        if (res != 0) {
            throw new SodiumException("Error when encrypting a message using secret stream.");
        }

        return messageEncoder.encode(cipher);
    }

    @Override
    public SecretStream.State cryptoSecretStreamInitPull(byte[] header, Key key) throws SodiumException {
        SecretStream.Checker.checkHeader(header);
        SecretStream.Checker.checkKey(key.getAsBytes());
        SecretStream.State state = new SecretStream.State.ByReference();

        int res = getSodium().crypto_secretstream_xchacha20poly1305_init_pull(state, header, key.getAsBytes());

        if (res != 0) {
            throw new SodiumException("Could not initialise a decryption state.");
        }

        return state;
    }

    @Override
    public String cryptoSecretStreamPull(SecretStream.State state, String cipher, byte[] tag) throws SodiumException {
        byte[] cipherBytes = messageEncoder.decode(cipher);
        BaseChecker.checkAtLeast("cipherLength", cipherBytes.length, SecretStream.ABYTES);
        BaseChecker.checkOptionalOutPointer("tag", tag);
        byte[] message = new byte[cipherBytes.length - SecretStream.ABYTES];

        int res = getSodium().crypto_secretstream_xchacha20poly1305_pull(
                state,
                message,
                null,
                tag,
                cipherBytes,
                cipherBytes.length,
                null,
                0L
        );

        if (res != 0) {
            throw new SodiumException("Error when decrypting a message using secret stream.");
        }

        return str(message);
    }

    @Override
    public void cryptoSecretStreamRekey(SecretStream.State state) {
        BaseChecker.requireNonNull("state", state);
        getSodium().crypto_secretstream_xchacha20poly1305_rekey(state);
    }


    //// -------------------------------------------|
    //// STREAM
    //// -------------------------------------------|

    @Override
    public void cryptoStreamChaCha20Keygen(byte[] key) {
        Stream.Checker.checkChaCha20Key(key);
        getSodium().crypto_stream_chacha20_keygen(key);
    }

    @Override
    public boolean cryptoStreamChaCha20(byte[] c, int cLen, byte[] nonce, byte[] key) {
        BaseChecker.checkArrayLength("c", c, cLen);
        Stream.Checker.checkChaCha20Nonce(nonce);
        Stream.Checker.checkChaCha20Key(key);
        return successful(getSodium().crypto_stream_chacha20(c, cLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamChaCha20Xor(byte[] cipher, byte[] message, int messageLen, byte[] nonce, byte[] key) {
        BaseChecker.checkArrayLength("message", message, messageLen);
        BaseChecker.checkExpectedMemorySize("cipher length", cipher.length, messageLen);
        Stream.Checker.checkChaCha20Nonce(nonce);
        Stream.Checker.checkChaCha20Key(key);
        return successful(getSodium().crypto_stream_chacha20_xor(cipher, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamChaCha20XorIc(byte[] cipher, byte[] message, int messageLen, byte[] nonce, long ic, byte[] key) {
        BaseChecker.checkArrayLength("message", message, messageLen);
        BaseChecker.checkExpectedMemorySize("cipher length", cipher.length, messageLen);
        Stream.Checker.checkChaCha20Nonce(nonce);
        Stream.Checker.checkChaCha20Key(key);
        return successful(getSodium().crypto_stream_chacha20_xor_ic(cipher, message, messageLen, nonce, ic, key));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoStreamChacha20XorIc(byte[] cipher, byte[] message, int messageLen, byte[] nonce, long ic, byte[] key) {
        return cryptoStreamChaCha20XorIc(cipher, message, messageLen, nonce, ic, key);
    }

    // Chacha20 Ietf

    @Override
    public void cryptoStreamChaCha20IetfKeygen(byte[] key) {
        Stream.Checker.checkChaCha20IetfKey(key);
        getSodium().crypto_stream_chacha20_ietf_keygen(key);
    }

    @Override
    public boolean cryptoStreamChaCha20Ietf(byte[] c, int cLen, byte[] nonce, byte[] key) {
        BaseChecker.checkArrayLength("c", c, cLen);
        Stream.Checker.checkChaCha20IetfNonce(nonce);
        Stream.Checker.checkChaCha20IetfKey(key);
        return successful(getSodium().crypto_stream_chacha20_ietf(c, cLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamChaCha20IetfXor(byte[] cipher, byte[] message, int messageLen, byte[] nonce, byte[] key) {
        BaseChecker.checkArrayLength("message", message, messageLen);
        BaseChecker.checkExpectedMemorySize("cipher length", cipher.length, messageLen);
        Stream.Checker.checkChaCha20IetfNonce(nonce);
        Stream.Checker.checkChaCha20IetfKey(key);
        return successful(getSodium().crypto_stream_chacha20_ietf_xor(cipher, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamChaCha20IetfXorIc(byte[] cipher, byte[] message, int messageLen, byte[] nonce, long ic, byte[] key) {
        BaseChecker.checkArrayLength("message", message, messageLen);
        BaseChecker.checkExpectedMemorySize("cipher length", cipher.length, messageLen);
        Stream.Checker.checkChaCha20IetfNonce(nonce);
        Stream.Checker.checkChaCha20IetfKey(key);
        return successful(getSodium().crypto_stream_chacha20_ietf_xor_ic(cipher, message, messageLen, nonce, ic, key));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoStreamChacha20IetfXorIc(byte[] cipher, byte[] message, int messageLen, byte[] nonce, long ic, byte[] key) {
        return cryptoStreamChaCha20IetfXorIc(cipher, message, messageLen, nonce, ic, key);
    }

    // Salsa20

    @Override
    public void cryptoStreamSalsa20Keygen(byte[] key) {
        Stream.Checker.checkSalsa20Key(key);
        getSodium().crypto_stream_salsa20_keygen(key);
    }

    @Override
    public boolean cryptoStreamSalsa20(byte[] c, int cLen, byte[] nonce, byte[] key) {
        BaseChecker.checkArrayLength("c", c, cLen);
        Stream.Checker.checkSalsa20Nonce(nonce);
        Stream.Checker.checkSalsa20Key(key);
        return successful(getSodium().crypto_stream_salsa20(c, cLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamSalsa20Xor(byte[] cipher, byte[] message, int messageLen, byte[] nonce, byte[] key) {
        BaseChecker.checkArrayLength("message", message, messageLen);
        BaseChecker.checkExpectedMemorySize("cipher length", cipher.length, messageLen);
        Stream.Checker.checkSalsa20Nonce(nonce);
        Stream.Checker.checkSalsa20Key(key);
        return successful(getSodium().crypto_stream_salsa20_xor(cipher, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamSalsa20XorIc(byte[] cipher, byte[] message, int messageLen, byte[] nonce, long ic, byte[] key) {
        BaseChecker.checkArrayLength("message", message, messageLen);
        BaseChecker.checkExpectedMemorySize("cipher length", cipher.length, messageLen);
        Stream.Checker.checkSalsa20Nonce(nonce);
        Stream.Checker.checkSalsa20Key(key);
        return successful(getSodium().crypto_stream_salsa20_xor_ic(cipher, message, messageLen, nonce, ic, key));
    }


    @Override
    public void cryptoStreamXSalsa20Keygen(byte[] key) {
        Stream.Checker.checkXSalsa20Key(key);
        getSodium().crypto_stream_xsalsa20_keygen(key);
    }

    @Override
    public boolean cryptoStreamXSalsa20(byte[] c, int cLen, byte[] nonce, byte[] key) {
        BaseChecker.checkArrayLength("c", c, cLen);
        Stream.Checker.checkXSalsa20Nonce(nonce);
        Stream.Checker.checkXSalsa20Key(key);
        return successful(getSodium().crypto_stream_xsalsa20(c, cLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamXSalsa20Xor(byte[] cipher, byte[] message, int messageLen, byte[] nonce, byte[] key) {
        BaseChecker.checkArrayLength("message", message, messageLen);
        BaseChecker.checkExpectedMemorySize("cipher length", cipher.length, messageLen);
        Stream.Checker.checkXSalsa20Nonce(nonce);
        Stream.Checker.checkXSalsa20Key(key);
        return successful(getSodium().crypto_stream_xsalsa20_xor(cipher, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamXSalsa20XorIc(byte[] cipher, byte[] message, int messageLen, byte[] nonce, long ic, byte[] key) {
        BaseChecker.checkArrayLength("message", message, messageLen);
        BaseChecker.checkExpectedMemorySize("cipher length", cipher.length, messageLen);
        Stream.Checker.checkXSalsa20Nonce(nonce);
        Stream.Checker.checkXSalsa20Key(key);
        return successful(getSodium().crypto_stream_xsalsa20_xor_ic(cipher, message, messageLen, nonce, ic, key));
    }

    // Lazy

    @Override
    public Key cryptoStreamKeygen(Stream.Method method) {
        BaseChecker.requireNonNull("method", method);
        switch (method) {
            case CHACHA20: {
                byte[] k = new byte[Stream.CHACHA20_KEYBYTES];
                cryptoStreamChaCha20Keygen(k);
                return Key.fromBytes(k);
            }
            case CHACHA20_IETF: {
                byte[] k = new byte[Stream.CHACHA20_IETF_KEYBYTES];
                cryptoStreamChaCha20Keygen(k);
                return Key.fromBytes(k);
            }
            case SALSA20: {
                byte[] k = new byte[Stream.SALSA20_KEYBYTES];
                cryptoStreamSalsa20Keygen(k);
                return Key.fromBytes(k);
            }
            case XSALSA20: {
                byte[] k = new byte[Stream.XSALSA20_KEYBYTES];
                cryptoStreamXSalsa20Keygen(k);
                return Key.fromBytes(k);
            }
            default:
                throw new IllegalArgumentException("Unsupported stream cipher method " + method);
        }
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public byte[] cryptoStream(byte[] nonce, Key key, Stream.Method method) {
        return cryptoStream(20, nonce, key, method);
    }

    @Override
    public byte[] cryptoStream(int bytes, byte[] nonce, Key key, Stream.Method method) {
        BaseChecker.requireNonNull("method", method);
        byte[] c = new byte[bytes];
        int cLen = c.length;
        switch (method) {
            case CHACHA20:
                cryptoStreamChaCha20(c, cLen, nonce, key.getAsBytes());
                break;
            case CHACHA20_IETF:
                cryptoStreamChaCha20Ietf(c, cLen, nonce, key.getAsBytes());
                break;
            case SALSA20:
                cryptoStreamSalsa20(c, cLen, nonce, key.getAsBytes());
                break;
            case XSALSA20:
                cryptoStreamXSalsa20(c, cLen, nonce, key.getAsBytes());
                break;
            default:
                throw new IllegalArgumentException("Unsupported stream cipher method " + method);
        }
        return c;
    }

    @Override
    public String cryptoStreamXor(String message, byte[] nonce, Key key, Stream.Method method) {
        byte[] mBytes = bytes(message);
        return messageEncoder.encode(cryptoStreamDefaultXor(mBytes, nonce, key, method));
    }

    @Override
    public String cryptoStreamXorDecrypt(String cipher, byte[] nonce, Key key, Stream.Method method) {
        return str(cryptoStreamDefaultXor(messageEncoder.decode(cipher), nonce, key, method));
    }


    @Override
    public String cryptoStreamXorIc(String message, byte[] nonce, long ic, Key key, Stream.Method method) {
        byte[] mBytes = bytes(message);
        return messageEncoder.encode(cryptoStreamDefaultXorIc(mBytes, nonce, ic, key, method));
    }

    @Override
    public String cryptoStreamXorIcDecrypt(String cipher, byte[] nonce, long ic, Key key, Stream.Method method) {
        byte[] cipherBytes = messageEncoder.decode(cipher);
        return str(cryptoStreamDefaultXorIc(cipherBytes, nonce, ic, key, method));
    }


    private byte[] cryptoStreamDefaultXor(byte[] messageBytes, byte[] nonce, Key key, Stream.Method method) {
        BaseChecker.requireNonNull("method", method);
        int mLen = messageBytes.length;
        byte[] cipher = new byte[mLen];
        switch (method) {
            case CHACHA20:
                cryptoStreamChaCha20Xor(cipher, messageBytes, mLen, nonce, key.getAsBytes());
                break;
            case CHACHA20_IETF:
                cryptoStreamChaCha20IetfXor(cipher, messageBytes, mLen, nonce, key.getAsBytes());
                break;
            case SALSA20:
                cryptoStreamSalsa20Xor(cipher, messageBytes, mLen, nonce, key.getAsBytes());
                break;
            case XSALSA20:
                cryptoStreamXSalsa20Xor(cipher, messageBytes, mLen, nonce, key.getAsBytes());
                break;
            default:
                throw new IllegalArgumentException("Unsupported stream cipher method " + method);
        }
        return cipher;
    }

    private byte[] cryptoStreamDefaultXorIc(byte[] messageBytes, byte[] nonce, long ic, Key key, Stream.Method method) {
        BaseChecker.requireNonNull("method", method);
        int mLen = messageBytes.length;
        byte[] cipher = new byte[mLen];
        switch (method) {
            case CHACHA20:
                cryptoStreamChaCha20XorIc(cipher, messageBytes, mLen, nonce, ic, key.getAsBytes());
                break;
            case CHACHA20_IETF:
                cryptoStreamChaCha20IetfXorIc(cipher, messageBytes, mLen, nonce, ic, key.getAsBytes());
                break;
            case SALSA20:
                cryptoStreamSalsa20XorIc(cipher, messageBytes, mLen, nonce, ic, key.getAsBytes());
                break;
            case XSALSA20:
                cryptoStreamXSalsa20XorIc(cipher, messageBytes, mLen, nonce, ic, key.getAsBytes());
                break;
            default:
                throw new IllegalArgumentException("Unsupported stream cipher method " + method);
        }
        return cipher;
    }


    //// -------------------------------------------|
    //// CRYPTO AUTH
    //// -------------------------------------------|

    @Override
    public boolean cryptoAuth(byte[] tag, byte[] in, int inLen, byte[] key) {
        Auth.Checker.checkTag(tag);
        BaseChecker.checkArrayLength("in", in, inLen);
        Auth.Checker.checkKey(key);
        return successful(getSodium().crypto_auth(tag, in, inLen, key));
    }

    @Override
    public boolean cryptoAuthVerify(byte[] tag, byte[] in, int inLen, byte[] key) {
        Auth.Checker.checkTag(tag);
        BaseChecker.checkArrayLength("in", in, inLen);
        Auth.Checker.checkKey(key);
        return successful(getSodium().crypto_auth_verify(tag, in, inLen, key));
    }

    @Override
    public void cryptoAuthKeygen(byte[] k) {
        Auth.Checker.checkKey(k);
        getSodium().crypto_auth_keygen(k);
    }


    @Override
    public Key cryptoAuthKeygen() {
        byte[] key = randomBytesBuf(Auth.KEYBYTES);
        cryptoAuthKeygen(key);
        return Key.fromBytes(key);
    }

    @Override
    public String cryptoAuth(String message, Key key) throws SodiumException {
        byte[] tag = new byte[Auth.BYTES];
        byte[] messageBytes = bytes(message);
        byte[] keyBytes = key.getAsBytes();
        boolean res = cryptoAuth(tag, messageBytes, messageBytes.length, keyBytes);

        if (!res) {
            throw new SodiumException("Could not apply auth tag to your message.");
        }

        return messageEncoder.encode(tag);
    }

    @Override
    public boolean cryptoAuthVerify(String tag, String message, Key key) {
        byte[] tagToBytes = messageEncoder.decode(tag);
        byte[] messageBytes = bytes(message);
        byte[] keyBytes = key.getAsBytes();
        return cryptoAuthVerify(tagToBytes, messageBytes, messageBytes.length, keyBytes);
    }


    @Override
    public void cryptoAuthHMACSha256Keygen(byte[] key) {
        Auth.Checker.checkHMACSha256Key(key);
        getSodium().crypto_auth_hmacsha256_keygen(key);
    }

    @Override
    public boolean cryptoAuthHMACSha256(byte[] out, byte[] in, int inLen, byte[] k) {
        Auth.Checker.checkHMACSha256Tag(out);
        BaseChecker.checkArrayLength("in", in, inLen);
        Auth.Checker.checkHMACSha256Key(k);
        return successful(getSodium().crypto_auth_hmacsha256(out, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha256Verify(byte[] h, byte[] in, int inLen, byte[] k) {
        Auth.Checker.checkHMACSha256Tag(h);
        BaseChecker.checkArrayLength("in", in, inLen);
        Auth.Checker.checkHMACSha256Key(k);
        return successful(getSodium().crypto_auth_hmacsha256_verify(h, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha256Init(Auth.StateHMAC256 state, byte[] key, int keyLen) {
        BaseChecker.checkArrayLength("key", key, keyLen);
        return successful(getSodium().crypto_auth_hmacsha256_init(state, key, keyLen));
    }

    @Override
    public boolean cryptoAuthHMACSha256Update(Auth.StateHMAC256 state, byte[] in, int inLen) {
        BaseChecker.checkArrayLength("in", in, inLen);
        return successful(getSodium().crypto_auth_hmacsha256_update(state, in, inLen));
    }

    @Override
    public boolean cryptoAuthHMACSha256Final(Auth.StateHMAC256 state, byte[] out) {
        Auth.Checker.checkHMACSha256Tag(out);
        return successful(getSodium().crypto_auth_hmacsha256_final(state, out));
    }


    @Override
    public void cryptoAuthHMACSha512Keygen(byte[] key) {
        Auth.Checker.checkHMACSha512Key(key);
        getSodium().crypto_auth_hmacsha512_keygen(key);
    }

    @Override
    public boolean cryptoAuthHMACSha512(byte[] out, byte[] in, int inLen, byte[] k) {
        Auth.Checker.checkHMACSha512Tag(out);
        BaseChecker.checkArrayLength("in", in, inLen);
        Auth.Checker.checkHMACSha512Key(k);
        return successful(getSodium().crypto_auth_hmacsha512(out, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha512Verify(byte[] h, byte[] in, int inLen, byte[] k) {
        Auth.Checker.checkHMACSha512Tag(h);
        BaseChecker.checkArrayLength("in", in, inLen);
        Auth.Checker.checkHMACSha512Key(k);
        return successful(getSodium().crypto_auth_hmacsha512_verify(h, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha512Init(Auth.StateHMAC512 state, byte[] key, int keyLen) {
        BaseChecker.checkArrayLength("key", key, keyLen);
        return successful(getSodium().crypto_auth_hmacsha512_init(state, key, keyLen));
    }

    @Override
    public boolean cryptoAuthHMACSha512Update(Auth.StateHMAC512 state, byte[] in, int inLen) {
        BaseChecker.checkArrayLength("in", in, inLen);
        return successful(getSodium().crypto_auth_hmacsha512_update(state, in, inLen));
    }

    @Override
    public boolean cryptoAuthHMACSha512Final(Auth.StateHMAC512 state, byte[] out) {
        Auth.Checker.checkHMACSha512Tag(out);
        return successful(getSodium().crypto_auth_hmacsha512_final(state, out));
    }


    @Override
    public void cryptoAuthHMACSha512256Keygen(byte[] key) {
        Auth.Checker.checkHMACSha512256Key(key);
        getSodium().crypto_auth_hmacsha512256_keygen(key);
    }

    @Override
    public boolean cryptoAuthHMACSha512256(byte[] out, byte[] in, int inLen, byte[] k) {
        Auth.Checker.checkHMACSha512256Tag(out);
        BaseChecker.checkArrayLength("in", in, inLen);
        Auth.Checker.checkHMACSha512256Key(k);
        return successful(getSodium().crypto_auth_hmacsha512256(out, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha512256Verify(byte[] h, byte[] in, int inLen, byte[] k) {
        Auth.Checker.checkHMACSha512256Tag(h);
        BaseChecker.checkArrayLength("in", in, inLen);
        Auth.Checker.checkHMACSha512256Key(k);
        return successful(getSodium().crypto_auth_hmacsha512256_verify(h, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha512256Init(Auth.StateHMAC512256 state, byte[] key, int keyLen) {
        BaseChecker.checkArrayLength("key", key, keyLen);
        return successful(getSodium().crypto_auth_hmacsha512256_init(state, key, keyLen));
    }

    @Override
    public boolean cryptoAuthHMACSha512256Update(Auth.StateHMAC512256 state, byte[] in, int inLen) {
        BaseChecker.checkArrayLength("in", in, inLen);
        return successful(getSodium().crypto_auth_hmacsha512256_update(state, in, inLen));
    }

    @Override
    public boolean cryptoAuthHMACSha512256Final(Auth.StateHMAC512256 state, byte[] out) {
        Auth.Checker.checkHMACSha512256Tag(out);
        return successful(getSodium().crypto_auth_hmacsha512256_final(state, out));
    }


    @Override
    public Key cryptoAuthHMACShaKeygen(Auth.Type type) {
        BaseChecker.requireNonNull("type", type);

        switch (type) {
            case SHA256: {
                byte[] k = new byte[Auth.HMACSHA256_KEYBYTES];
                cryptoAuthHMACSha256Keygen(k);
                return Key.fromBytes(k);
            }
            case SHA512: {
                byte[] k = new byte[Auth.HMACSHA512_KEYBYTES];
                cryptoAuthHMACSha512Keygen(k);
                return Key.fromBytes(k);
            }
            case SHA512256: {
                byte[] k = new byte[Auth.HMACSHA512256_KEYBYTES];
                cryptoAuthHMACSha512256Keygen(k);
                return Key.fromBytes(k);
            }
            default:
                throw new IllegalArgumentException("Unsupported auth type " + type);
        }
    }

    @Override
    public String cryptoAuthHMACSha(Auth.Type type, String in, Key key) {
        BaseChecker.requireNonNull("type", type);
        byte[] inBytes = bytes(in);
        byte[] keyBytes = key.getAsBytes();
        int inByteLen = inBytes.length;
        switch (type) {
            case SHA256: {
                byte[] out = new byte[Auth.HMACSHA256_BYTES];
                cryptoAuthHMACSha256(out, inBytes, inByteLen, keyBytes);
                return messageEncoder.encode(out);
            }
            case SHA512: {
                byte[] out = new byte[Auth.HMACSHA512_BYTES];
                cryptoAuthHMACSha512(out, inBytes, inByteLen, keyBytes);
                return messageEncoder.encode(out);
            }
            case SHA512256: {
                byte[] out = new byte[Auth.HMACSHA512256_BYTES];
                cryptoAuthHMACSha512256(out, inBytes, inByteLen, keyBytes);
                return messageEncoder.encode(out);
            }
            default:
                throw new IllegalArgumentException("Unsupported auth type " + type);
        }
    }

    @Override
    public boolean cryptoAuthHMACShaVerify(Auth.Type type, String h, String in, Key key) {
        BaseChecker.requireNonNull("type", type);
        byte[] authBytes = messageEncoder.decode(h);
        byte[] inBytes = bytes(in);
        byte[] keyBytes = key.getAsBytes();
        int inByteLen = inBytes.length;
        switch (type) {
            case SHA256:
                return cryptoAuthHMACSha256Verify(authBytes, inBytes, inByteLen, keyBytes);
            case SHA512:
                return cryptoAuthHMACSha512Verify(authBytes, inBytes, inByteLen, keyBytes);
            case SHA512256:
                return cryptoAuthHMACSha512256Verify(authBytes, inBytes, inByteLen, keyBytes);
            default:
                throw new IllegalArgumentException("Unsupported auth type " + type);
        }
    }

    @Override
    public boolean cryptoAuthHMACShaInit(Auth.StateHMAC256 state, Key key) {
        byte[] keyBytes = key.getAsBytes();
        return cryptoAuthHMACSha256Init(state, keyBytes, keyBytes.length);
    }

    @Override
    public boolean cryptoAuthHMACShaUpdate(Auth.StateHMAC256 state, String in) {
        byte[] inBytes = bytes(in);
        int inByteLen = inBytes.length;
        return cryptoAuthHMACSha256Update(state, inBytes, inByteLen);
    }

    @Override
    public String cryptoAuthHMACShaFinal(Auth.StateHMAC256 state) throws SodiumException {
        byte[] out = new byte[Auth.HMACSHA256_BYTES];
        boolean res = cryptoAuthHMACSha256Final(state, out);
        if (!res) {
            throw new SodiumException("Could not finalise SHA Hash.");
        }
        return messageEncoder.encode(out);
    }

    @Override
    public boolean cryptoAuthHMACShaInit(Auth.StateHMAC512 state, Key key) {
        byte[] keyBytes = key.getAsBytes();
        return cryptoAuthHMACSha512Init(state, keyBytes, keyBytes.length);
    }

    @Override
    public boolean cryptoAuthHMACShaUpdate(Auth.StateHMAC512 state, String in) {
        byte[] inBytes = bytes(in);
        int inByteLen = inBytes.length;
        return cryptoAuthHMACSha512Update(state, inBytes, inByteLen);
    }

    @Override
    public String cryptoAuthHMACShaFinal(Auth.StateHMAC512 state) throws SodiumException {
        byte[] out = new byte[Auth.HMACSHA512_BYTES];
        boolean res = cryptoAuthHMACSha512Final(state, out);
        if (!res) {
            throw new SodiumException("Could not finalise HMAC Sha 512.");
        }
        return messageEncoder.encode(out);
    }

    @Override
    public boolean cryptoAuthHMACShaInit(Auth.StateHMAC512256 state, Key key) {
        byte[] keyBytes = key.getAsBytes();
        return cryptoAuthHMACSha512256Init(state, keyBytes, keyBytes.length);
    }

    @Override
    public boolean cryptoAuthHMACShaUpdate(Auth.StateHMAC512256 state, String in) {
        byte[] inBytes = bytes(in);
        int inByteLen = inBytes.length;
        return cryptoAuthHMACSha512256Update(state, inBytes, inByteLen);
    }

    @Override
    public String cryptoAuthHMACShaFinal(Auth.StateHMAC512256 state) throws SodiumException {
        byte[] out = new byte[Auth.HMACSHA512256_BYTES];
        boolean res = cryptoAuthHMACSha512256Final(state, out);
        if (!res) {
            throw new SodiumException("Could not finalise HMAC Sha 512256.");
        }
        return messageEncoder.encode(out);
    }

    //// -------------------------------------------|
    //// SHORT HASH
    //// -------------------------------------------|

    @Override
    public boolean cryptoShortHash(byte[] out, byte[] in, int inLen, byte[] key) {
        BaseChecker.checkArrayLength("in", in, inLen);
        ShortHash.Checker.checkHash(out);
        ShortHash.Checker.checkKey(key);
        return successful(getSodium().crypto_shorthash(out, in, inLen, key));
    }

    @Override
    public void cryptoShortHashKeygen(byte[] k) {
        ShortHash.Checker.checkKey(k);
        getSodium().crypto_shorthash_keygen(k);
    }

    @Override
    public String cryptoShortHash(byte[] inBytes, Key key) throws SodiumException {
        byte[] keyBytes = key.getAsBytes();
        ShortHash.Checker.checkKey(keyBytes);
        byte[] out = new byte[ShortHash.BYTES];
        if (getSodium().crypto_shorthash(out, inBytes, inBytes.length, keyBytes) != 0) {
            throw new SodiumException("Failed short-input hashing.");
        }
        return sodiumBin2Hex(out);
    }

    @Override
    public String cryptoShortHashStr(String in, Key key) throws SodiumException {
        return cryptoShortHash(bytes(in), key);
    }

    @Override
    public String cryptoShortHashHex(String hexIn, Key key) throws SodiumException {
        return cryptoShortHash(hexToBytes(hexIn), key);
    }

    @Override
    public Key cryptoShortHashKeygen() {
        byte[] key = randomBytesBuf(ShortHash.KEYBYTES);
        getSodium().crypto_shorthash_keygen(key);
        return Key.fromBytes(key);
    }


    //// -------------------------------------------|
    //// GENERIC HASH
    //// -------------------------------------------|

    @Override
    public boolean cryptoGenericHash(byte[] out, int outLen, byte[] in, int inLen, byte[] key, int keyLen) {
        BaseChecker.checkArrayLength("out", out, outLen);
        GenericHash.Checker.checkOutputLength(outLen);
        BaseChecker.checkArrayLength("in", in, inLen);
        GenericHash.Checker.checkKey(key, keyLen);
        return successful(getSodium().crypto_generichash(out, outLen, in, inLen, key, keyLen));
    }

    @Override
    public boolean cryptoGenericHash(byte[] out, int outLen, byte[] in, int inLen) {
        return cryptoGenericHash(out, outLen, in, inLen, null, 0);
    }

    @Override
    public boolean cryptoGenericHashInit(GenericHash.State state, byte[] key, int keyLength, int outLen) {
        GenericHash.Checker.checkKey(key, keyLength);
        GenericHash.Checker.checkOutputLength(outLen);
        return successful(getSodium().crypto_generichash_init(state.getPointer(), key, keyLength, outLen));
    }

    @Override
    public boolean cryptoGenericHashInit(GenericHash.State state, int outLen) {
        return cryptoGenericHashInit(state, null, 0, outLen);
    }

    @Override
    public boolean cryptoGenericHashUpdate(GenericHash.State state, byte[] in, int inLen) {
        BaseChecker.checkArrayLength("in", in, inLen);
        return successful(getSodium().crypto_generichash_update(state.getPointer(), in, inLen));
    }

    @Override
    public boolean cryptoGenericHashFinal(GenericHash.State state, byte[] out, int outLen) {
        BaseChecker.checkArrayLength("out", out, outLen);
        GenericHash.Checker.checkOutputLength(outLen);
        return successful(getSodium().crypto_generichash_final(state.getPointer(), out, outLen));
    }

    @Override
    public void cryptoGenericHashKeygen(byte[] k) {
        GenericHash.Checker.checkKey(k);
        getSodium().crypto_generichash_keygen(k);
    }

    // -- lazy

    @Override
    public Key cryptoGenericHashKeygen() {
        byte[] key = new byte[GenericHash.KEYBYTES];
        cryptoGenericHashKeygen(key);
        return Key.fromBytes(key);
    }

    @Override
    public Key cryptoGenericHashKeygen(int size) {
        return Key.generate(this, size);
    }

    @Override
    public String cryptoGenericHash(String in, Key key) throws SodiumException {
        byte[] message = bytes(in);
        byte[] keyBytes = key == null ? null : key.getAsBytes();

        byte[] hash = new byte[GenericHash.BYTES];
        boolean res = cryptoGenericHash(hash, hash.length, message, message.length, keyBytes, keyBytes == null ? 0 : keyBytes.length);

        if (!res) {
            throw new SodiumException("Could not hash the message.");
        }

        return messageEncoder.encode(hash);
    }

    @Override
    public String cryptoGenericHash(String in) throws SodiumException {
        return cryptoGenericHash(in, null);
    }

    @Override
    public boolean cryptoGenericHashInit(GenericHash.State state, Key key, int outLen) {
        byte[] keyBytes = key == null ? null : key.getAsBytes();
        return cryptoGenericHashInit(state, keyBytes, keyBytes == null ? 0 : keyBytes.length, outLen);
    }

    @Override
    public boolean cryptoGenericHashUpdate(GenericHash.State state, String in) {
        byte[] inBytes = bytes(in);
        return cryptoGenericHashUpdate(state, inBytes, inBytes.length);
    }

    @Override
    public String cryptoGenericHashFinal(GenericHash.State state, int outLen) throws SodiumException {
        byte[] hash = new byte[outLen];
        boolean res = cryptoGenericHashFinal(state, hash, hash.length);
        if (!res) {
            throw new SodiumException("Could not finalise the hashing process.");
        }
        return messageEncoder.encode(hash);
    }


    //// -------------------------------------------|
    //// AEAD
    //// -------------------------------------------|

    @Override
    public void cryptoAeadChaCha20Poly1305Keygen(byte[] key) {
        AEAD.Checker.checkChaCha20Poly1305Key(key);
        getSodium().crypto_aead_chacha20poly1305_keygen(key);
    }

    @Override
    public boolean cryptoAeadChaCha20Poly1305Encrypt(byte[] c, long[] cLen, byte[] m, int mLen, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        BaseChecker.checkArrayLength("mLen", m, mLen);
        AEAD.Checker.checkChaCha20Poly1305CipherLength(c, mLen, cLen != null);
        BaseChecker.checkOptionalOutPointer("cLen", cLen);
        BaseChecker.checkOptionalArrayLength("ad", ad, adLen);
        AEAD.Checker.checkChaCha20Poly1305Nonce(nPub);
        AEAD.Checker.checkChaCha20Poly1305Key(k);
        return successful(getSodium().crypto_aead_chacha20poly1305_encrypt(c, cLen, m, mLen, ad, adLen, null, nPub, k));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoAeadChaCha20Poly1305Encrypt(byte[] c, long[] cLen, byte[] m, int mLen, byte[] ad, int adLen, byte[] nSec, byte[] nPub, byte[] k) {
        return cryptoAeadChaCha20Poly1305Encrypt(c, cLen, m, mLen, ad, adLen, nPub, k);
    }

    @Override
    public boolean cryptoAeadChaCha20Poly1305Decrypt(byte[] m, long[] mLen, byte[] c, int cLen, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        BaseChecker.checkArrayLength("cLen", c, cLen);
        AEAD.Checker.checkChaCha20Poly1305DecryptedMessageLength(m, cLen, mLen != null);
        BaseChecker.checkOptionalOutPointer("mLen", mLen);
        BaseChecker.checkOptionalArrayLength("ad", ad, adLen);
        AEAD.Checker.checkChaCha20Poly1305Nonce(nPub);
        AEAD.Checker.checkChaCha20Poly1305Key(k);
        return successful(getSodium().crypto_aead_chacha20poly1305_decrypt(m, mLen, null, c, cLen, ad, adLen, nPub, k));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoAeadChaCha20Poly1305Decrypt(byte[] m, long[] mLen, byte[] nSec, byte[] c, int cLen, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        return cryptoAeadChaCha20Poly1305Decrypt(m, mLen, c, cLen, ad, adLen, nPub, k);
    }

    @Override
    public boolean cryptoAeadChaCha20Poly1305EncryptDetached(byte[] c, byte[] mac, long[] macLenAddress, byte[] m, int mLen, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        BaseChecker.checkArrayLength("mLen", m, mLen);
        BaseChecker.checkExpectedMemorySize("c", c.length, mLen);
        AEAD.Checker.checkChaCha20Poly1305Mac(mac, macLenAddress != null);
        BaseChecker.checkOptionalOutPointer("macLenAddress", macLenAddress);
        BaseChecker.checkOptionalArrayLength("ad", ad, adLen);
        AEAD.Checker.checkChaCha20Poly1305Nonce(nPub);
        AEAD.Checker.checkChaCha20Poly1305Key(k);
        return successful(getSodium().crypto_aead_chacha20poly1305_encrypt_detached(c, mac, macLenAddress, m, mLen, ad, adLen, null, nPub, k));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoAeadChaCha20Poly1305EncryptDetached(byte[] c, byte[] mac, long[] macLenAddress, byte[] m, int mLen, byte[] ad, int adLen, byte[] nSec, byte[] nPub, byte[] k) {
        return cryptoAeadChaCha20Poly1305EncryptDetached(c, mac, macLenAddress, m, mLen, ad, adLen, nPub, k);
    }

    @Override
    public boolean cryptoAeadChaCha20Poly1305DecryptDetached(byte[] m, byte[] c, int cLen, byte[] mac, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        BaseChecker.checkArrayLength("cLen", c, cLen);
        BaseChecker.checkExpectedMemorySize("m", m.length, cLen);
        AEAD.Checker.checkChaCha20Poly1305Mac(mac, false);
        BaseChecker.checkOptionalArrayLength("ad", ad, adLen);
        AEAD.Checker.checkChaCha20Poly1305Nonce(nPub);
        AEAD.Checker.checkChaCha20Poly1305Key(k);
        return successful(getSodium().crypto_aead_chacha20poly1305_decrypt_detached(m, null, c, cLen, mac, ad, adLen, nPub, k));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoAeadChaCha20Poly1305DecryptDetached(byte[] m, byte[] nSec, byte[] c, int cLen, byte[] mac, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        return cryptoAeadChaCha20Poly1305DecryptDetached(m, c, cLen, mac, ad, adLen, nPub, k);
    }

    @Override
    public void cryptoAeadChaCha20Poly1305IetfKeygen(byte[] key) {
        AEAD.Checker.checkChaCha20Poly1305IetfKey(key);
        getSodium().crypto_aead_chacha20poly1305_ietf_keygen(key);
    }

    @Override
    public boolean cryptoAeadChaCha20Poly1305IetfEncrypt(byte[] c, long[] cLen, byte[] m, int mLen, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        BaseChecker.checkArrayLength("mLen", m, mLen);
        AEAD.Checker.checkChaCha20Poly1305IetfCipherLength(c, mLen, cLen != null);
        BaseChecker.checkOptionalOutPointer("cLen", cLen);
        BaseChecker.checkOptionalArrayLength("ad", ad, adLen);
        AEAD.Checker.checkChaCha20Poly1305IetfNonce(nPub);
        AEAD.Checker.checkChaCha20Poly1305IetfKey(k);
        return successful(getSodium().crypto_aead_chacha20poly1305_ietf_encrypt(c, cLen, m, mLen, ad, adLen, null, nPub, k));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoAeadChaCha20Poly1305IetfEncrypt(byte[] c, long[] cLen, byte[] m, int mLen, byte[] ad, int adLen, byte[] nSec, byte[] nPub, byte[] k) {
        return cryptoAeadChaCha20Poly1305IetfEncrypt(c, cLen, m, mLen, ad, adLen, nPub, k);
    }

    @Override
    public boolean cryptoAeadChaCha20Poly1305IetfDecrypt(byte[] m, long[] mLen, byte[] c, int cLen, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        BaseChecker.checkArrayLength("cLen", c, cLen);
        AEAD.Checker.checkChaCha20Poly1305IetfDecryptedMessageLength(m, cLen, mLen != null);
        BaseChecker.checkOptionalOutPointer("mLen", mLen);
        BaseChecker.checkOptionalArrayLength("ad", ad, adLen);
        AEAD.Checker.checkChaCha20Poly1305IetfNonce(nPub);
        AEAD.Checker.checkChaCha20Poly1305IetfKey(k);
        return successful(getSodium().crypto_aead_chacha20poly1305_ietf_decrypt(m, mLen, null, c, cLen, ad, adLen, nPub, k));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoAeadChaCha20Poly1305IetfDecrypt(byte[] m, long[] mLen, byte[] nSec, byte[] c, int cLen, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        return cryptoAeadChaCha20Poly1305IetfDecrypt(m, mLen, c, cLen, ad, adLen, nPub, k);
    }

    @Override
    public boolean cryptoAeadChaCha20Poly1305IetfEncryptDetached(byte[] c, byte[] mac, long[] macLenAddress, byte[] m, int mLen, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        BaseChecker.checkArrayLength("mLen", m, mLen);
        BaseChecker.checkExpectedMemorySize("c", c.length, mLen);
        AEAD.Checker.checkChaCha20Poly1305IetfMac(mac, macLenAddress != null);
        BaseChecker.checkOptionalOutPointer("macLenAddress", macLenAddress);
        BaseChecker.checkOptionalArrayLength("ad", ad, adLen);
        AEAD.Checker.checkChaCha20Poly1305IetfNonce(nPub);
        AEAD.Checker.checkChaCha20Poly1305IetfKey(k);
        return successful(getSodium().crypto_aead_chacha20poly1305_ietf_encrypt_detached(c, mac, macLenAddress, m, mLen, ad, adLen, null, nPub, k));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoAeadChaCha20Poly1305IetfEncryptDetached(byte[] c, byte[] mac, long[] macLenAddress, byte[] m, int mLen, byte[] ad, int adLen, byte[] nSec, byte[] nPub, byte[] k) {
        return cryptoAeadChaCha20Poly1305IetfEncryptDetached(c, mac, macLenAddress, m, mLen, ad, adLen, nPub, k);
    }

    @Override
    public boolean cryptoAeadChaCha20Poly1305IetfDecryptDetached(byte[] m, byte[] c, int cLen, byte[] mac, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        BaseChecker.checkArrayLength("cLen", c, cLen);
        BaseChecker.checkExpectedMemorySize("m", m.length, cLen);
        AEAD.Checker.checkChaCha20Poly1305IetfMac(mac, false);
        BaseChecker.checkOptionalArrayLength("ad", ad, adLen);
        AEAD.Checker.checkChaCha20Poly1305IetfNonce(nPub);
        AEAD.Checker.checkChaCha20Poly1305IetfKey(k);
        return successful(getSodium().crypto_aead_chacha20poly1305_ietf_decrypt_detached(m, null, c, cLen, mac, ad, adLen, nPub, k));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoAeadChaCha20Poly1305IetfDecryptDetached(byte[] m, byte[] nSec, byte[] c, int cLen, byte[] mac, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        return cryptoAeadChaCha20Poly1305IetfDecryptDetached(m, c, cLen, mac, ad, adLen, nPub, k);
    }

    @Override
    public void cryptoAeadXChaCha20Poly1305IetfKeygen(byte[] k) {
        AEAD.Checker.checkXChaCha20Poly1305IetfKey(k);
        getSodium().crypto_aead_xchacha20poly1305_ietf_keygen(k);
    }

    @Override
    public boolean cryptoAeadXChaCha20Poly1305IetfEncrypt(byte[] c, long[] cLen, byte[] m, int mLen, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        BaseChecker.checkArrayLength("mLen", m, mLen);
        AEAD.Checker.checkXChaCha20Poly1305IetfCipherLength(c, mLen, cLen != null);
        BaseChecker.checkOptionalOutPointer("cLen", cLen);
        BaseChecker.checkOptionalArrayLength("ad", ad, adLen);
        AEAD.Checker.checkXChaCha20Poly1305IetfNonce(nPub);
        AEAD.Checker.checkXChaCha20Poly1305IetfKey(k);
        return successful(getSodium().crypto_aead_xchacha20poly1305_ietf_encrypt(c, cLen, m, mLen, ad, adLen, null, nPub, k));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoAeadXChaCha20Poly1305IetfEncrypt(byte[] c, long[] cLen, byte[] m, int mLen, byte[] ad, int adLen, byte[] nSec, byte[] nPub, byte[] k) {
        return cryptoAeadXChaCha20Poly1305IetfEncrypt(c, cLen, m, mLen, ad, adLen, nPub, k);
    }

    @Override
    public boolean cryptoAeadXChaCha20Poly1305IetfDecrypt(byte[] m, long[] mLen, byte[] c, int cLen, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        BaseChecker.checkArrayLength("cLen", c, cLen);
        AEAD.Checker.checkXChaCha20Poly1305IetfDecryptedMessageLength(m, cLen, mLen != null);
        BaseChecker.checkOptionalOutPointer("mLen", mLen);
        BaseChecker.checkOptionalArrayLength("ad", ad, adLen);
        AEAD.Checker.checkXChaCha20Poly1305IetfNonce(nPub);
        AEAD.Checker.checkXChaCha20Poly1305IetfKey(k);
        return successful(getSodium().crypto_aead_xchacha20poly1305_ietf_decrypt(m, mLen, null, c, cLen, ad, adLen, nPub, k));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoAeadXChaCha20Poly1305IetfDecrypt(byte[] m, long[] mLen, byte[] nSec, byte[] c, int cLen, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        return cryptoAeadXChaCha20Poly1305IetfDecrypt(m, mLen, c, cLen, ad, adLen, nPub, k);
    }

    @Override
    public boolean cryptoAeadXChaCha20Poly1305IetfEncryptDetached(byte[] c, byte[] mac, long[] macLenAddress, byte[] m, int mLen, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        BaseChecker.checkArrayLength("mLen", m, mLen);
        BaseChecker.checkExpectedMemorySize("c", c.length, mLen);
        AEAD.Checker.checkXChaCha20Poly1305IetfMac(mac, macLenAddress != null);
        BaseChecker.checkOptionalOutPointer("macLenAddress", macLenAddress);
        BaseChecker.checkOptionalArrayLength("ad", ad, adLen);
        AEAD.Checker.checkXChaCha20Poly1305IetfNonce(nPub);
        AEAD.Checker.checkXChaCha20Poly1305IetfKey(k);
        return successful(getSodium().crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, macLenAddress, m, mLen, ad, adLen, null, nPub, k));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoAeadXChaCha20Poly1305IetfEncryptDetached(byte[] c, byte[] mac, long[] macLenAddress, byte[] m, int mLen, byte[] ad, int adLen, byte[] nSec, byte[] nPub, byte[] k) {
        return cryptoAeadXChaCha20Poly1305IetfEncryptDetached(c, mac, macLenAddress, m, mLen, ad, adLen, nPub, k);
    }

    @Override
    public boolean cryptoAeadXChaCha20Poly1305IetfDecryptDetached(byte[] m, byte[] c, int cLen, byte[] mac, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        BaseChecker.checkArrayLength("cLen", c, cLen);
        BaseChecker.checkExpectedMemorySize("m", m.length, cLen);
        AEAD.Checker.checkXChaCha20Poly1305IetfMac(mac, false);
        BaseChecker.checkOptionalArrayLength("ad", ad, adLen);
        AEAD.Checker.checkXChaCha20Poly1305IetfNonce(nPub);
        AEAD.Checker.checkXChaCha20Poly1305IetfKey(k);
        return successful(getSodium().crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m, null, c, cLen, mac, ad, adLen, nPub, k));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoAeadXChaCha20Poly1305IetfDecryptDetached(byte[] m, byte[] nSec, byte[] c, int cLen, byte[] mac, byte[] ad, int adLen, byte[] nPub, byte[] k) {
        return cryptoAeadXChaCha20Poly1305IetfDecryptDetached(m, c, cLen, mac, ad, adLen, nPub, k);
    }

    @Override
    public void cryptoAeadAES256GCMKeygen(byte[] key) {
        AEAD.Checker.checkAes256GcmKey(key);
        getSodium().crypto_aead_aes256gcm_keygen(key);
    }

    @Override
    public boolean cryptoAeadAES256GCMEncrypt(byte[] cipher, long[] cipherLen, byte[] message, int messageLen, byte[] additionalData, int additionalDataLen, byte[] nPub, byte[] key) {
        BaseChecker.checkArrayLength("messageLen", message, messageLen);
        AEAD.Checker.checkAes256GcmCipherLength(cipher, messageLen, cipherLen != null);
        BaseChecker.checkOptionalOutPointer("cipherLen", cipherLen);
        BaseChecker.checkOptionalArrayLength("additionalDataLen", additionalData, additionalDataLen);
        AEAD.Checker.checkAes256GcmNonce(nPub);
        AEAD.Checker.checkAes256GcmKey(key);
        return successful(getSodium().crypto_aead_aes256gcm_encrypt(cipher, cipherLen, message, messageLen, additionalData, additionalDataLen, null, nPub, key));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoAeadAES256GCMEncrypt(byte[] cipher, long[] cipherLen, byte[] message, int messageLen, byte[] additionalData, int additionalDataLen, byte[] nSec, byte[] nPub, byte[] key) {
        return cryptoAeadAES256GCMEncrypt(cipher, cipherLen, message, messageLen, additionalData, additionalDataLen, nPub, key);
    }

    @Override
    public boolean cryptoAeadAES256GCMDecrypt(byte[] message, long[] messageLen, byte[] cipher, int cipherLen, byte[] additionalData, int additionalDataLen, byte[] nPub, byte[] key) {
        BaseChecker.checkArrayLength("cipherLen", cipher, cipherLen);
        AEAD.Checker.checkAes256GcmDecryptedMessageLength(message, cipherLen, messageLen != null);
        BaseChecker.checkOptionalOutPointer("messageLen", messageLen);
        BaseChecker.checkOptionalArrayLength("additionalData", additionalData, additionalDataLen);
        AEAD.Checker.checkAes256GcmNonce(nPub);
        AEAD.Checker.checkAes256GcmKey(key);
        return successful(getSodium().crypto_aead_aes256gcm_decrypt(message, messageLen, null, cipher, cipherLen, additionalData, additionalDataLen, nPub, key));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoAeadAES256GCMDecrypt(byte[] message, long[] messageLen, byte[] nSec, byte[] cipher, int cipherLen, byte[] additionalData, int additionalDataLen, byte[] nPub, byte[] key) {
        return cryptoAeadAES256GCMDecrypt(message, messageLen, cipher, cipherLen, additionalData, additionalDataLen, nPub, key);
    }

    @Override
    public boolean cryptoAeadAES256GCMEncryptDetached(byte[] cipher, byte[] mac, long[] macLenAddress, byte[] message, int messageLen, byte[] additionalData, int additionalDataLen, byte[] nPub, byte[] key) {
        BaseChecker.checkArrayLength("messageLen", message, messageLen);
        BaseChecker.checkExpectedMemorySize("cipher", cipher.length, messageLen);
        AEAD.Checker.checkAes256GcmMac(mac, macLenAddress != null);
        BaseChecker.checkOptionalOutPointer("macLenAddress", macLenAddress);
        BaseChecker.checkOptionalArrayLength("additionalDataLen", additionalData, additionalDataLen);
        AEAD.Checker.checkAes256GcmNonce(nPub);
        AEAD.Checker.checkAes256GcmKey(key);
        return successful(getSodium().crypto_aead_aes256gcm_encrypt_detached(cipher, mac, macLenAddress, message, messageLen, additionalData, additionalDataLen, null, nPub, key));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoAeadAES256GCMEncryptDetached(byte[] cipher, byte[] mac, long[] macLenAddress, byte[] message, int messageLen, byte[] additionalData, int additionalDataLen, byte[] nSec, byte[] nPub, byte[] key) {
        return cryptoAeadAES256GCMEncryptDetached(cipher, mac, macLenAddress, message, messageLen, additionalData, additionalDataLen, nPub, key);
    }

    @Override
    public boolean cryptoAeadAES256GCMDecryptDetached(byte[] message, byte[] cipher, int cipherLen, byte[] mac, byte[] additionalData, int additionalDataLen, byte[] nPub, byte[] key) {
        BaseChecker.checkArrayLength("cipherLen", cipher, cipherLen);
        BaseChecker.checkExpectedMemorySize("message", message.length, cipherLen);
        AEAD.Checker.checkAes256GcmMac(mac, false);
        BaseChecker.checkOptionalArrayLength("additionalData", additionalData, additionalDataLen);
        AEAD.Checker.checkAes256GcmNonce(nPub);
        AEAD.Checker.checkAes256GcmKey(key);
        return successful(getSodium().crypto_aead_aes256gcm_decrypt_detached(message, null, cipher, cipherLen, mac, additionalData, additionalDataLen, nPub, key));
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public boolean cryptoAeadAES256GCMDecryptDetached(byte[] message, byte[] nSec, byte[] cipher, int cipherLen, byte[] mac, byte[] additionalData, int additionalDataLen, byte[] nPub, byte[] key) {
        return cryptoAeadAES256GCMDecryptDetached(message, cipher, cipherLen, mac, additionalData, additionalDataLen, nPub, key);
    }

    @Override
    public boolean cryptoAeadAES256GCMIsAvailable() {
        return getSodium().crypto_aead_aes256gcm_is_available() == 1;
    }


    // -- lazy

    @Override
    public Key keygen(AEAD.Method method) {
        switch (method) {
            case CHACHA20_POLY1305:
                byte[] key = randomBytesBuf(AEAD.CHACHA20POLY1305_KEYBYTES);
                cryptoAeadChaCha20Poly1305Keygen(key);
                return Key.fromBytes(key);
            case CHACHA20_POLY1305_IETF:
                byte[] key2 = randomBytesBuf(AEAD.CHACHA20POLY1305_IETF_KEYBYTES);
                cryptoAeadChaCha20Poly1305IetfKeygen(key2);
                return Key.fromBytes(key2);
            case XCHACHA20_POLY1305_IETF:
                byte[] key3 = randomBytesBuf(AEAD.XCHACHA20POLY1305_IETF_KEYBYTES);
                cryptoAeadXChaCha20Poly1305IetfKeygen(key3);
                return Key.fromBytes(key3);
            case AES256GCM:
                byte[] key4 = randomBytesBuf(AEAD.AES256GCM_KEYBYTES);
                cryptoAeadAES256GCMKeygen(key4);
                return Key.fromBytes(key4);
        }
        return null;
    }

    @Override
    public String encrypt(String m, String additionalData, byte[] nPub, Key k, AEAD.Method method) {
        BaseChecker.requireNonNull("method", method);

        byte[] messageBytes = bytes(m);
        byte[] additionalDataBytes = additionalData == null ? null : bytes(additionalData);
        int additionalBytesLen = additionalData == null ? 0 : additionalDataBytes.length;
        byte[] keyBytes = k.getAsBytes();

        switch (method) {
            case CHACHA20_POLY1305: {
                byte[] cipherBytes;
                cipherBytes = new byte[messageBytes.length + AEAD.CHACHA20POLY1305_ABYTES];
                cryptoAeadChaCha20Poly1305Encrypt(
                        cipherBytes,
                        null,
                        messageBytes,
                        messageBytes.length,
                        additionalDataBytes,
                        additionalBytesLen,
                        nPub,
                        keyBytes
                );
                return messageEncoder.encode(cipherBytes);
            }
            case CHACHA20_POLY1305_IETF: {
                byte[] cipherBytes = new byte[messageBytes.length + AEAD.CHACHA20POLY1305_IETF_ABYTES];
                cryptoAeadChaCha20Poly1305IetfEncrypt(
                        cipherBytes,
                        null,
                        messageBytes,
                        messageBytes.length,
                        additionalDataBytes,
                        additionalBytesLen,
                        nPub,
                        keyBytes
                );
                return messageEncoder.encode(cipherBytes);
            }
            case XCHACHA20_POLY1305_IETF: {
                byte[] cipherBytes = new byte[messageBytes.length + AEAD.XCHACHA20POLY1305_IETF_ABYTES];
                cryptoAeadXChaCha20Poly1305IetfEncrypt(
                        cipherBytes,
                        null,
                        messageBytes,
                        messageBytes.length,
                        additionalDataBytes,
                        additionalBytesLen,
                        nPub,
                        keyBytes
                );
                return messageEncoder.encode(cipherBytes);
            }
            case AES256GCM: {
                byte[] cipherBytes = new byte[messageBytes.length + AEAD.AES256GCM_ABYTES];
                cryptoAeadAES256GCMEncrypt(
                        cipherBytes,
                        null,
                        messageBytes,
                        messageBytes.length,
                        additionalDataBytes,
                        additionalBytesLen,
                        nPub,
                        keyBytes
                );
                return messageEncoder.encode(cipherBytes);
            }
            default:
                throw new IllegalArgumentException("Unsupported AEAD method: " + method);
        }
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public String encrypt(String m, String additionalData, byte[] nSec, byte[] nPub, Key k, AEAD.Method method) {
        return encrypt(m, additionalData, nPub, k, method);
    }

    @Override
    public String decrypt(String cipher, String additionalData, byte[] nPub, Key k, AEAD.Method method) throws AEADBadTagException {
        BaseChecker.requireNonNull("method", method);

        byte[] cipherBytes = messageEncoder.decode(cipher);
        byte[] additionalDataBytes = additionalData == null ? null : bytes(additionalData);
        int additionalBytesLen = additionalData == null ? 0 : additionalDataBytes.length;
        byte[] keyBytes = k.getAsBytes();

        switch (method) {
            case CHACHA20_POLY1305: {
                byte[] messageBytes = new byte[cipherBytes.length - AEAD.CHACHA20POLY1305_ABYTES];
                if (!cryptoAeadChaCha20Poly1305Decrypt(
                        messageBytes,
                        null,
                        cipherBytes,
                        cipherBytes.length,
                        additionalDataBytes,
                        additionalBytesLen,
                        nPub,
                        keyBytes
                )) {
                    throw new AEADBadTagException();
                }
                return str(messageBytes);
            }
            case CHACHA20_POLY1305_IETF: {
                byte[] messageBytes = new byte[cipherBytes.length - AEAD.CHACHA20POLY1305_IETF_ABYTES];
                if (!cryptoAeadChaCha20Poly1305IetfDecrypt(
                        messageBytes,
                        null,
                        cipherBytes,
                        cipherBytes.length,
                        additionalDataBytes,
                        additionalBytesLen,
                        nPub,
                        keyBytes
                )) {
                    throw new AEADBadTagException();
                }
                return str(messageBytes);
            }
            case XCHACHA20_POLY1305_IETF: {
                byte[] messageBytes = new byte[cipherBytes.length - AEAD.XCHACHA20POLY1305_IETF_ABYTES];
                if (!cryptoAeadXChaCha20Poly1305IetfDecrypt(
                        messageBytes,
                        null,
                        cipherBytes,
                        cipherBytes.length,
                        additionalDataBytes,
                        additionalBytesLen,
                        nPub,
                        keyBytes
                )) {
                    throw new AEADBadTagException();
                }
                return str(messageBytes);
            }
            case AES256GCM: {
                byte[] messageBytes = new byte[cipherBytes.length - AEAD.AES256GCM_ABYTES];
                if (!cryptoAeadAES256GCMDecrypt(
                        messageBytes,
                        null,
                        cipherBytes,
                        cipherBytes.length,
                        additionalDataBytes,
                        additionalBytesLen,
                        nPub,
                        keyBytes
                )) {
                    throw new AEADBadTagException();
                }
                return str(messageBytes);
            }
            default:
                throw new IllegalArgumentException("Unsupported AEAD method: " + method);
        }
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public String decrypt(String cipher, String additionalData, byte[] nSec, byte[] nPub, Key k, AEAD.Method method) throws AEADBadTagException {
        return decrypt(cipher, additionalData, nPub, k, method);
    }

    @Override
    public DetachedEncrypt encryptDetached(String m, String additionalData, byte[] nPub, Key k, AEAD.Method method) {
        BaseChecker.requireNonNull("method", method);

        byte[] messageBytes = bytes(m);
        byte[] additionalDataBytes = additionalData == null ? null : bytes(additionalData);
        int additionalBytesLen = additionalData == null ? 0 : additionalDataBytes.length;
        byte[] keyBytes = k.getAsBytes();
        byte[] cipherBytes = new byte[messageBytes.length];

        switch (method) {
            case CHACHA20_POLY1305: {
                byte[] macBytes = new byte[AEAD.CHACHA20POLY1305_ABYTES];

                cryptoAeadChaCha20Poly1305EncryptDetached(
                        cipherBytes,
                        macBytes,
                        null,
                        messageBytes,
                        messageBytes.length,
                        additionalDataBytes,
                        additionalBytesLen,
                        nPub,
                        keyBytes
                );
                return new DetachedEncrypt(cipherBytes, macBytes);
            }
            case CHACHA20_POLY1305_IETF: {
                byte[] macBytes = new byte[AEAD.CHACHA20POLY1305_IETF_ABYTES];
                cryptoAeadChaCha20Poly1305IetfEncryptDetached(
                        cipherBytes,
                        macBytes,
                        null,
                        messageBytes,
                        messageBytes.length,
                        additionalDataBytes,
                        additionalBytesLen,
                        nPub,
                        keyBytes
                );
                return new DetachedEncrypt(cipherBytes, macBytes);
            }
            case XCHACHA20_POLY1305_IETF: {
                byte[] macBytes = new byte[AEAD.XCHACHA20POLY1305_IETF_ABYTES];
                cryptoAeadXChaCha20Poly1305IetfEncryptDetached(
                        cipherBytes,
                        macBytes,
                        null,
                        messageBytes,
                        messageBytes.length,
                        additionalDataBytes,
                        additionalBytesLen,
                        nPub,
                        keyBytes
                );
                return new DetachedEncrypt(cipherBytes, macBytes);
            }
            case AES256GCM: {
                byte[] macBytes = new byte[AEAD.AES256GCM_ABYTES];
                cryptoAeadAES256GCMEncryptDetached(
                        cipherBytes,
                        macBytes,
                        null,
                        messageBytes,
                        messageBytes.length,
                        additionalDataBytes,
                        additionalBytesLen,
                        nPub,
                        keyBytes
                );
                return new DetachedEncrypt(cipherBytes, macBytes);
            }
            default:
                throw new IllegalArgumentException("Unsupported AEAD method: " + method);
        }
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public DetachedEncrypt encryptDetached(String m, String additionalData, byte[] nSec, byte[] nPub, Key k, AEAD.Method method) {
        return encryptDetached(m, additionalData, nPub, k, method);
    }

    @Override
    public DetachedDecrypt decryptDetached(DetachedEncrypt detachedEncrypt, String additionalData, byte[] nPub, Key k, AEAD.Method method) throws AEADBadTagException {
        byte[] cipherBytes = detachedEncrypt.getCipher();
        byte[] additionalDataBytes = additionalData == null ? null : bytes(additionalData);
        int additionalBytesLen = additionalData == null ? 0 : additionalDataBytes.length;
        byte[] keyBytes = k.getAsBytes();
        byte[] messageBytes = new byte[cipherBytes.length];
        byte[] macBytes = detachedEncrypt.getMac();

        switch (method) {
            case CHACHA20_POLY1305:
                if (!cryptoAeadChaCha20Poly1305DecryptDetached(
                        messageBytes,
                        cipherBytes,
                        cipherBytes.length,
                        macBytes,
                        additionalDataBytes,
                        additionalBytesLen,
                        nPub,
                        keyBytes
                )) {
                    throw new AEADBadTagException();
                }
                return new DetachedDecrypt(messageBytes, macBytes, charset);
            case CHACHA20_POLY1305_IETF:
                if (!cryptoAeadChaCha20Poly1305IetfDecryptDetached(
                        messageBytes,
                        cipherBytes,
                        cipherBytes.length,
                        macBytes,
                        additionalDataBytes,
                        additionalBytesLen,
                        nPub,
                        keyBytes
                )) {
                    throw new AEADBadTagException();
                }
                return new DetachedDecrypt(messageBytes, macBytes, charset);
            case XCHACHA20_POLY1305_IETF:
                if (!cryptoAeadXChaCha20Poly1305IetfDecryptDetached(
                        messageBytes,
                        cipherBytes,
                        cipherBytes.length,
                        macBytes,
                        additionalDataBytes,
                        additionalBytesLen,
                        nPub,
                        keyBytes
                )) {
                    throw new AEADBadTagException();
                }
                return new DetachedDecrypt(messageBytes, macBytes, charset);
            case AES256GCM:
                if (!cryptoAeadAES256GCMDecryptDetached(
                        messageBytes,
                        cipherBytes,
                        cipherBytes.length,
                        macBytes,
                        additionalDataBytes,
                        additionalBytesLen,
                        nPub,
                        keyBytes
                )) {
                    throw new AEADBadTagException();
                }
                return new DetachedDecrypt(messageBytes, macBytes, charset);
            default:
                throw new IllegalArgumentException("Unsupported AEAD method: " + method);
        }
    }

    @Override
    @SuppressWarnings("removal") // yep, we know, this is the backward-compatible implementation of the deprecated API
    @Deprecated(forRemoval = true, since = "6.0.0")
    public DetachedDecrypt decryptDetached(DetachedEncrypt detachedEncrypt, String additionalData, byte[] nSec, byte[] nPub, Key k, AEAD.Method method) throws AEADBadTagException {
        return decryptDetached(detachedEncrypt, additionalData, nPub, k, method);
    }

    //// -------------------------------------------|
    //// Ristretto255
    //// -------------------------------------------|

    @Override
    public boolean cryptoCoreRistretto255IsValidPoint(byte[] point) {
        return point.length == Ristretto255.RISTRETTO255_BYTES
                && getSodium().crypto_core_ristretto255_is_valid_point(point) == 1;
    }

    @Override
    public void cryptoCoreRistretto255Random(byte[] point) {
        Ristretto255.Checker.checkPoint("point", point);

        getSodium().crypto_core_ristretto255_random(point);
    }

    @Override
    public boolean cryptoCoreRistretto255FromHash(byte[] point, byte[] hash) {
        Ristretto255.Checker.checkPoint("point", point);
        Ristretto255.Checker.checkHash("hash", hash);

        return successful(getSodium().crypto_core_ristretto255_from_hash(point, hash));
    }

    @Override
    public boolean cryptoScalarmultRistretto255(byte[] result, byte[] n, byte[] point) {
        Ristretto255.Checker.checkPoint("result", result);
        Ristretto255.Checker.checkScalar("n", n);
        Ristretto255.Checker.checkPoint("point", point);

        return successful(getSodium().crypto_scalarmult_ristretto255(result, n, point));
    }

    @Override
    public boolean cryptoScalarmultRistretto255Base(byte[] result, byte[] n) {
        Ristretto255.Checker.checkPoint("result", result);
        Ristretto255.Checker.checkScalar("n", n);

        return successful(getSodium().crypto_scalarmult_ristretto255_base(result, n));
    }

    @Override
    public boolean cryptoCoreRistretto255Add(byte[] result, byte[] p, byte[] q) {
        Ristretto255.Checker.checkPoint("result", result);
        Ristretto255.Checker.checkPoint("p", p);
        Ristretto255.Checker.checkPoint("q", q);

        return successful(getSodium().crypto_core_ristretto255_add(result, p, q));
    }

    @Override
    public boolean cryptoCoreRistretto255Sub(byte[] result, byte[] p, byte[] q) {
        Ristretto255.Checker.checkPoint("result", result);
        Ristretto255.Checker.checkPoint("p", p);
        Ristretto255.Checker.checkPoint("q", q);

        return successful(getSodium().crypto_core_ristretto255_sub(result, p, q));
    }

    @Override
    public void cryptoCoreRistretto255ScalarRandom(byte[] scalar) {
        Ristretto255.Checker.checkScalar("scalar", scalar);

        getSodium().crypto_core_ristretto255_scalar_random(scalar);
    }

    @Override
    public void cryptoCoreRistretto255ScalarReduce(byte[] result, byte[] scalar) {
        Ristretto255.Checker.checkScalar("result", result);
        Ristretto255.Checker.checkNonReducedScalar("scalar", scalar);

        getSodium().crypto_core_ristretto255_scalar_reduce(result, scalar);
    }

    @Override
    public boolean cryptoCoreRistretto255ScalarInvert(byte[] result, byte[] scalar) {
        Ristretto255.Checker.checkScalar("result", result);
        Ristretto255.Checker.checkScalar("scalar", scalar);

        return successful(getSodium().crypto_core_ristretto255_scalar_invert(result, scalar));
    }

    @Override
    public void cryptoCoreRistretto255ScalarNegate(byte[] result, byte[] scalar) {
        Ristretto255.Checker.checkScalar("result", result);
        Ristretto255.Checker.checkScalar("scalar", scalar);

        getSodium().crypto_core_ristretto255_scalar_negate(result, scalar);
    }

    @Override
    public void cryptoCoreRistretto255ScalarComplement(byte[] result, byte[] scalar) {
        Ristretto255.Checker.checkScalar("result", result);
        Ristretto255.Checker.checkScalar("scalar", scalar);

        getSodium().crypto_core_ristretto255_scalar_complement(result, scalar);
    }

    @Override
    public void cryptoCoreRistretto255ScalarAdd(byte[] result, byte[] x, byte[] y) {
        Ristretto255.Checker.checkScalar("result", result);
        Ristretto255.Checker.checkScalar("x", x);
        Ristretto255.Checker.checkScalar("y", y);

        getSodium().crypto_core_ristretto255_scalar_add(result, x, y);
    }

    @Override
    public void cryptoCoreRistretto255ScalarSub(byte[] result, byte[] x, byte[] y) {
        Ristretto255.Checker.checkScalar("result", result);
        Ristretto255.Checker.checkScalar("x", x);
        Ristretto255.Checker.checkScalar("y", y);

        getSodium().crypto_core_ristretto255_scalar_sub(result, x, y);
    }

    @Override
    public void cryptoCoreRistretto255ScalarMul(byte[] result, byte[] x, byte[] y) {
        Ristretto255.Checker.checkScalar("result", result);
        Ristretto255.Checker.checkScalar("x", x);
        Ristretto255.Checker.checkScalar("y", y);

        getSodium().crypto_core_ristretto255_scalar_mul(result, x, y);
    }


    // -- lazy

    @Override
    public boolean cryptoCoreRistretto255IsValidPoint(String point) {
        if (point == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255IsValidPoint(messageEncoder.decode(point));
    }

    @Override
    public RistrettoPoint cryptoCoreRistretto255Random() {
        byte[] point = Ristretto255.pointBuffer();
        cryptoCoreRistretto255Random(point);

        return RistrettoPoint.fromBytes(this, point);
    }

    @Override
    public RistrettoPoint cryptoCoreRistretto255FromHash(String hash) throws SodiumException {
        if (hash == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255FromHash(messageEncoder.decode(hash));
    }


    @Override
    public RistrettoPoint cryptoCoreRistretto255FromHash(byte[] hash) throws SodiumException {
        byte[] point = Ristretto255.pointBuffer();

        if (!cryptoCoreRistretto255FromHash(point, hash)) {
            throw new SodiumException("Conversion from hash to Ristretto point failed");
        }

        return RistrettoPoint.fromBytes(this, point);
    }

    @Override
    public RistrettoPoint cryptoScalarmultRistretto255(BigInteger n, RistrettoPoint point)
            throws SodiumException {
        if (n == null || point == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoScalarmultRistretto255(Ristretto255.scalarToBytes(n), point);
    }

    @Override
    public RistrettoPoint cryptoScalarmultRistretto255(String nEnc, RistrettoPoint point)
            throws SodiumException {
        if (nEnc == null || point == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoScalarmultRistretto255(messageEncoder.decode(nEnc), point);
    }

    @Override
    public RistrettoPoint cryptoScalarmultRistretto255(byte[] n, RistrettoPoint point)
            throws SodiumException {

        byte[] result = Ristretto255.pointBuffer();

        if (!cryptoScalarmultRistretto255(result, n, point.toBytes())) {
            throw new SodiumException(
                    "Scalar multiplication failed. The resulting point was the identity element.");
        }

        return RistrettoPoint.fromBytes(this, result);
    }

    @Override
    public RistrettoPoint cryptoScalarmultRistretto255Base(BigInteger n) throws SodiumException {
        if (n == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }
        return cryptoScalarmultRistretto255Base(Ristretto255.scalarToBytes(n));
    }

    @Override
    public RistrettoPoint cryptoScalarmultRistretto255Base(String nEnc)
            throws SodiumException {
        if (nEnc == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoScalarmultRistretto255Base(messageEncoder.decode(nEnc));
    }

    @Override
    public RistrettoPoint cryptoScalarmultRistretto255Base(byte[] n) throws SodiumException {
        byte[] result = Ristretto255.pointBuffer();

        if (!cryptoScalarmultRistretto255Base(result, n)) {
            throw new SodiumException(
                    "Scalar multiplication failed. n was 0.");
        }

        return RistrettoPoint.fromBytes(this, result);
    }

    @Override
    public RistrettoPoint cryptoCoreRistretto255Add(RistrettoPoint p, RistrettoPoint q)
            throws SodiumException {
        if (p == null || q == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        byte[] result = Ristretto255.pointBuffer();
        if (!cryptoCoreRistretto255Add(result, p.toBytes(), q.toBytes())) {
            throw new SodiumException("Either p or q was not a valid point.");
        }

        return RistrettoPoint.fromBytes(this, result);
    }

    @Override
    public RistrettoPoint cryptoCoreRistretto255Sub(RistrettoPoint p, RistrettoPoint q)
            throws SodiumException {

        if (p == null || q == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        byte[] result = Ristretto255.pointBuffer();
        if (!cryptoCoreRistretto255Sub(result, p.toBytes(), q.toBytes())) {
            throw new SodiumException("Either p or q was not a valid point.");
        }

        return RistrettoPoint.fromBytes(this, result);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarRandom() {
        byte[] scalar = Ristretto255.scalarBuffer();
        cryptoCoreRistretto255ScalarRandom(scalar);

        return Ristretto255.bytesToScalar(scalar);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarReduce(BigInteger scalar) {
        if (scalar == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarReduce(Ristretto255.scalarToBytes(scalar, false));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarReduce(String scalarEnc) {
        if (scalarEnc == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarReduce(messageEncoder.decode(scalarEnc));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarReduce(byte[] scalar) {
        byte[] result = Ristretto255.scalarBuffer();
        cryptoCoreRistretto255ScalarReduce(result, scalar);

        return Ristretto255.bytesToScalar(result);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarInvert(BigInteger scalar)
            throws SodiumException {
        if (scalar == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarInvert(Ristretto255.scalarToBytes(scalar));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarInvert(String scalarEnc)
            throws SodiumException {
        if (scalarEnc == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarInvert(messageEncoder.decode(scalarEnc));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarInvert(byte[] scalar) throws SodiumException {
        byte[] result = Ristretto255.scalarBuffer();

        if (!cryptoCoreRistretto255ScalarInvert(result, scalar)) {
            throw new SodiumException("Scalar inversion failed. Did you pass 0?");
        }

        return Ristretto255.bytesToScalar(result);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarNegate(BigInteger scalar) {
        if (scalar == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarNegate(Ristretto255.scalarToBytes(scalar));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarNegate(String scalarEnc) {
        if (scalarEnc == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarNegate(messageEncoder.decode(scalarEnc));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarNegate(byte[] scalar) {
        byte[] result = Ristretto255.scalarBuffer();
        cryptoCoreRistretto255ScalarNegate(result, scalar);

        return Ristretto255.bytesToScalar(result);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarComplement(BigInteger scalar) {
        if (scalar == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarComplement(Ristretto255.scalarToBytes(scalar));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarComplement(String scalarEnc) {
        if (scalarEnc == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarComplement(messageEncoder.decode(scalarEnc));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarComplement(byte[] scalar) {
        byte[] result = Ristretto255.scalarBuffer();
        cryptoCoreRistretto255ScalarComplement(result, scalar);

        return Ristretto255.bytesToScalar(result);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarAdd(BigInteger x, BigInteger y) {
        if (x == null || y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarAdd(
                Ristretto255.scalarToBytes(x), Ristretto255.scalarToBytes(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarAdd(BigInteger x, String y) {
        if (x == null || y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarAdd(Ristretto255.scalarToBytes(x), messageEncoder.decode(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarAdd(String x, BigInteger y) {
        if (x == null || y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarAdd(messageEncoder.decode(x), Ristretto255.scalarToBytes(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarAdd(String x, String y) {
        if (x == null || y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarAdd(messageEncoder.decode(x), messageEncoder.decode(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarAdd(String x, byte[] y) {
        if (x == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarAdd(messageEncoder.decode(x), y);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarAdd(byte[] x, String y) {
        if (y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarAdd(x, messageEncoder.decode(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarAdd(BigInteger x, byte[] y) {
        if (x == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarAdd(Ristretto255.scalarToBytes(x), y);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarAdd(byte[] x, BigInteger y) {
        if (y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarAdd(x, Ristretto255.scalarToBytes(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarAdd(byte[] x, byte[] y) {
        byte[] result = Ristretto255.scalarBuffer();
        cryptoCoreRistretto255ScalarAdd(result, x, y);

        return Ristretto255.bytesToScalar(result);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarSub(BigInteger x, BigInteger y) {
        if (x == null || y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarSub(
                Ristretto255.scalarToBytes(x), Ristretto255.scalarToBytes(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarSub(BigInteger x, String y) {
        if (x == null || y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarSub(Ristretto255.scalarToBytes(x), messageEncoder.decode(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarSub(String x, BigInteger y) {
        if (x == null || y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarSub(messageEncoder.decode(x), Ristretto255.scalarToBytes(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarSub(String x, String y) {
        if (x == null || y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarSub(messageEncoder.decode(x), messageEncoder.decode(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarSub(String x, byte[] y) {
        if (x == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarSub(messageEncoder.decode(x), y);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarSub(byte[] x, String y) {
        if (y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarSub(x, messageEncoder.decode(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarSub(BigInteger x, byte[] y) {
        if (x == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarSub(Ristretto255.scalarToBytes(x), y);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarSub(byte[] x, BigInteger y) {
        if (y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarSub(x, Ristretto255.scalarToBytes(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarSub(byte[] x, byte[] y) {
        byte[] result = Ristretto255.scalarBuffer();
        cryptoCoreRistretto255ScalarSub(result, x, y);

        return Ristretto255.bytesToScalar(result);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarMul(BigInteger x, BigInteger y) {
        if (x == null || y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarMul(
                Ristretto255.scalarToBytes(x), Ristretto255.scalarToBytes(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarMul(BigInteger x, String y) {
        if (x == null || y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarMul(Ristretto255.scalarToBytes(x), messageEncoder.decode(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarMul(String x, BigInteger y) {
        if (x == null || y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarMul(messageEncoder.decode(x), Ristretto255.scalarToBytes(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarMul(String x, String y) {
        if (x == null || y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarMul(messageEncoder.decode(x), messageEncoder.decode(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarMul(String x, byte[] y) {
        if (x == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarMul(messageEncoder.decode(x), y);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarMul(byte[] x, String y) {
        if (y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarMul(x, messageEncoder.decode(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarMul(BigInteger x, byte[] y) {
        if (x == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarMul(Ristretto255.scalarToBytes(x), y);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarMul(byte[] x, BigInteger y) {
        if (y == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255ScalarMul(x, Ristretto255.scalarToBytes(y));
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarMul(byte[] x, byte[] y) {
        byte[] result = Ristretto255.scalarBuffer();
        cryptoCoreRistretto255ScalarMul(result, x, y);

        return Ristretto255.bytesToScalar(result);
    }

    //// -------------------------------------------|
    //// CONVENIENCE
    //// -------------------------------------------|

    @Override
    public <T> T res(int res, T object) {
        return (res != 0) ? null : object;
    }

    @Override
    public boolean successful(int res) {
        return (res == 0);
    }

    @Override
    public String str(byte[] bs) {
        return new String(bs, charset);
    }

    @Override
    public String str(byte[] bs, Charset charset) {
        if (charset == null) {
            return new String(bs, this.charset);
        }
        return new String(bs, charset);
    }

    @Override
    public byte[] bytes(String s) {
        return s.getBytes(charset);
    }

    /**
     * Encodes the given bytes, using this {@link LazySodium}'s associated
     * {@link MessageEncoder}.
     *
     * @param bytes the bytes to encode
     * @return the encoded string
     */
    public String encodeToString(byte[] bytes) {
        return messageEncoder.encode(bytes);
    }

    /**
     * Decodes the given string to bytes, using this {@link LazySodium}'s associated
     * {@link MessageEncoder}.
     *
     * @param encoded the encoded string
     * @return the decoded bytes
     */
    public byte[] decodeFromString(String encoded) {
        return messageEncoder.decode(encoded);
    }

    @Override
    public boolean wrongLen(byte[] bs, int shouldBe) {
        return bs.length != shouldBe;
    }

    @Override
    public boolean wrongLen(int byteLength, int shouldBe) {
        return byteLength != shouldBe;
    }

    @Override
    public boolean wrongLen(int byteLength, long shouldBe) {
        return byteLength != shouldBe;
    }

    @Override
    public byte[] removeNulls(byte[] bs) {
        // First determine how many bytes to
        // cut off the end by checking total of null bytes
        int totalBytesToCut = 0;
        for (int i = bs.length - 1; i >= 0; i--) {
            byte b = bs[i];
            if (b == 0) {
                totalBytesToCut++;
            }
        }

        // ... then we now can copy across the array
        // without the null bytes.
        int newLengthOfBs = bs.length - totalBytesToCut;
        byte[] trimmed = new byte[newLengthOfBs];
        System.arraycopy(bs, 0, trimmed, 0, newLengthOfBs);

        return trimmed;
    }

    static byte[] encodeToAsciiz(String str) {
        byte[] bytes = str.getBytes(StandardCharsets.US_ASCII);
        byte[] bytesWithZero = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0, bytesWithZero, 0, bytes.length);
        return bytesWithZero;
    }

    static String decodeAsciiz(byte[] bytes) throws SodiumException {
        int zeroPos = -1;
        for (int i = 0; i < bytes.length; ++i) {
            if (bytes[i] == 0) {
                zeroPos = i;
                break;
            }
        }
        if (zeroPos < 0) {
            // this should not happen for results from sodium, so...?
            throw new SodiumException("Zero terminator missing in presumably ASCIIZ data");
        }
        return new String(bytes, 0, zeroPos, StandardCharsets.US_ASCII);
    }

    public abstract Sodium getSodium();


    // --

    //// -------------------------------------------|
    //// MAIN
    //// -------------------------------------------|
    // --
    public static void main(String[] args) throws SodiumException {

    }


}
