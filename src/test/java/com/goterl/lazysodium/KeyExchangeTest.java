/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.KeyExchange;
import com.goterl.lazysodium.utils.KeyPair;
import com.goterl.lazysodium.utils.SessionPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class KeyExchangeTest extends BaseTest {
    private KeyExchange.Lazy keyExchangeLazy;
    private KeyExchange.Native keyExchangeNative;

    @BeforeAll
    public void before() {
        keyExchangeLazy = lazySodium;
        keyExchangeNative = lazySodium;
    }

    @Test
    public void generateKeyPairLazy() throws SodiumException {
        KeyPair keys = keyExchangeLazy.cryptoKxKeypair();
        assertNotNull(keys);
    }

    @Test
    public void generateKeyPairNative() {
        byte[] publicKey = new byte[KeyExchange.PUBLICKEYBYTES];
        byte[] secretKey = new byte[KeyExchange.SECRETKEYBYTES];
        boolean success = keyExchangeNative.cryptoKxKeypair(publicKey, secretKey);
        assertTrue(success);
        assertTrue(countZeros(publicKey) < 20);
        assertTrue(countZeros(secretKey) < 20);
    }

    @Test
    public void rejectBadKeyLengthNative() {
        byte[] publicKey = new byte[KeyExchange.PUBLICKEYBYTES];
        byte[] secretKey = new byte[KeyExchange.SECRETKEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxKeypair(new byte[KeyExchange.PUBLICKEYBYTES - 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxKeypair(new byte[KeyExchange.PUBLICKEYBYTES + 1], secretKey));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxKeypair(publicKey, new byte[KeyExchange.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxKeypair(publicKey, new byte[KeyExchange.SECRETKEYBYTES + 1]));
    }

    @Test
    public void generateDeterministicPublicKeyPairLazy() throws SodiumException {
        byte[] seed = lazySodium.randomBytesBuf(KeyExchange.SEEDBYTES);
        KeyPair keys = keyExchangeLazy.cryptoKxKeypair(seed);
        KeyPair keys2 = keyExchangeLazy.cryptoKxKeypair(seed);

        assertEquals(keys.getPublicKey().getAsHexString(), keys2.getPublicKey().getAsHexString());
        assertEquals(keys.getSecretKey().getAsHexString(), keys2.getSecretKey().getAsHexString());
    }

    @Test
    public void rejectBadSeedLengthLazy() {
        assertThrows(IllegalArgumentException.class, () -> keyExchangeLazy.cryptoKxKeypair(new byte[KeyExchange.SEEDBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeLazy.cryptoKxKeypair(new byte[KeyExchange.SEEDBYTES + 1]));
    }

    @Test
    public void cryptoKxSeedKeypairChecks() {
        byte[] publicKey = new byte[KeyExchange.PUBLICKEYBYTES];
        byte[] secretKey = new byte[KeyExchange.SECRETKEYBYTES];
        byte[] seed = new byte[KeyExchange.SEEDBYTES];
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxSeedKeypair(publicKey, secretKey, new byte[KeyExchange.SEEDBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxSeedKeypair(publicKey, secretKey, new byte[KeyExchange.SEEDBYTES + 1]));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxSeedKeypair(new byte[KeyExchange.PUBLICKEYBYTES - 1], secretKey, seed));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxSeedKeypair(new byte[KeyExchange.PUBLICKEYBYTES + 1], secretKey, seed));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxSeedKeypair(publicKey, new byte[KeyExchange.SECRETKEYBYTES - 1], seed));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxSeedKeypair(publicKey, new byte[KeyExchange.SECRETKEYBYTES + 1], seed));
    }

    @Test
    public void generateDeterministicSecretKeyPairNative() {
        byte[] seed = lazySodium.randomBytesBuf(KeyExchange.SEEDBYTES);
        byte[] publicKey1 = new byte[KeyExchange.PUBLICKEYBYTES];
        byte[] secretKey1 = new byte[KeyExchange.SECRETKEYBYTES];
        boolean success1 = keyExchangeNative.cryptoKxSeedKeypair(publicKey1, secretKey1, seed);
        byte[] publicKey2 = new byte[KeyExchange.PUBLICKEYBYTES];
        byte[] secretKey2 = new byte[KeyExchange.SECRETKEYBYTES];
        boolean success2 = keyExchangeNative.cryptoKxSeedKeypair(publicKey2, secretKey2, seed);

        assertTrue(success1);
        assertTrue(success2);
        assertArrayEquals(publicKey1, publicKey2);
        assertArrayEquals(secretKey1, secretKey2);
    }

    @Test
    public void generateSessionPairLazy() throws SodiumException {
        // Generate the client's keypair
        KeyPair clientKeys = keyExchangeLazy.cryptoKxKeypair();

        // Generate the server keypair
        KeyPair serverKeys = keyExchangeLazy.cryptoKxKeypair();

        SessionPair clientSession = keyExchangeLazy.cryptoKxClientSessionKeys(clientKeys, serverKeys);
        SessionPair serverSession = keyExchangeLazy.cryptoKxServerSessionKeys(serverKeys, clientKeys);

        // The Rx of the client should equal the Tx of the server and vice versa
        assertEquals(clientSession.getRxString(), serverSession.getTxString());
        assertEquals(clientSession.getTxString(), serverSession.getRxString());
    }

    @Test
    public void generateSessionPairNative() {
        byte[] clientPk = new byte[KeyExchange.PUBLICKEYBYTES];
        byte[] clientSk = new byte[KeyExchange.SECRETKEYBYTES];
        byte[] serverPk = new byte[KeyExchange.PUBLICKEYBYTES];
        byte[] serverSk = new byte[KeyExchange.PUBLICKEYBYTES];
        byte[] clientRx = new byte[KeyExchange.SESSIONKEYBYTES];
        byte[] clientTx = new byte[KeyExchange.SESSIONKEYBYTES];
        byte[] serverRx = new byte[KeyExchange.SESSIONKEYBYTES];
        byte[] serverTx = new byte[KeyExchange.SESSIONKEYBYTES];

        boolean clientKeysSuccess = keyExchangeNative.cryptoKxKeypair(clientPk, clientSk);
        boolean serverKeysSuccess = keyExchangeNative.cryptoKxKeypair(serverPk, serverSk);

        assertTrue(clientKeysSuccess);
        assertTrue(serverKeysSuccess);

        boolean clientSessionSuccess = keyExchangeNative.cryptoKxClientSessionKeys(clientRx, clientTx, clientPk, clientSk, serverPk);
        boolean serverSessionSuccess = keyExchangeNative.cryptoKxServerSessionKeys(serverRx, serverTx, serverPk, serverSk, clientPk);

        assertTrue(clientSessionSuccess);
        assertTrue(serverSessionSuccess);

        // The Rx of the client should equal the Tx of the server and vice versa
        assertArrayEquals(clientRx, serverTx);
        assertArrayEquals(clientTx, serverRx);
    }

    @Test
    public void cryptoKxClientSessionKeysNativeChecks() {
        byte[] rx = new byte[KeyExchange.SESSIONKEYBYTES];
        byte[] tx = new byte[KeyExchange.SESSIONKEYBYTES];
        byte[] clientPk = new byte[KeyExchange.PUBLICKEYBYTES];
        byte[] clientSk = new byte[KeyExchange.SECRETKEYBYTES];
        byte[] serverPk = new byte[KeyExchange.PUBLICKEYBYTES];
        byte[] serverSk = new byte[KeyExchange.PUBLICKEYBYTES];

        keyExchangeNative.cryptoKxKeypair(clientPk, clientSk);
        keyExchangeNative.cryptoKxKeypair(serverPk, serverSk);

        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxClientSessionKeys(new byte[KeyExchange.SESSIONKEYBYTES - 1], tx, clientPk, clientSk, serverPk));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxClientSessionKeys(new byte[KeyExchange.SESSIONKEYBYTES + 1], tx, clientPk, clientSk, serverPk));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxClientSessionKeys(rx, new byte[KeyExchange.SESSIONKEYBYTES - 1], clientPk, clientSk, serverPk));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxClientSessionKeys(rx, new byte[KeyExchange.SESSIONKEYBYTES + 1], clientPk, clientSk, serverPk));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxClientSessionKeys(rx, tx, new byte[KeyExchange.PUBLICKEYBYTES - 1], clientSk, serverPk));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxClientSessionKeys(rx, tx, new byte[KeyExchange.PUBLICKEYBYTES + 1], clientSk, serverPk));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxClientSessionKeys(rx, tx, clientPk, new byte[KeyExchange.SECRETKEYBYTES - 1], serverPk));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxClientSessionKeys(rx, tx, clientPk, new byte[KeyExchange.SECRETKEYBYTES + 1], serverPk));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxClientSessionKeys(rx, tx, clientPk, clientSk, new byte[KeyExchange.PUBLICKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxClientSessionKeys(rx, tx, clientPk, clientSk, new byte[KeyExchange.PUBLICKEYBYTES + 1]));
    }

    @Test
    public void cryptoKxServerSessionKeysNativeChecks() {
        byte[] rx = new byte[KeyExchange.SESSIONKEYBYTES];
        byte[] tx = new byte[KeyExchange.SESSIONKEYBYTES];
        byte[] serverPk = new byte[KeyExchange.PUBLICKEYBYTES];
        byte[] serverSk = new byte[KeyExchange.SECRETKEYBYTES];
        byte[] clientPk = new byte[KeyExchange.PUBLICKEYBYTES];
        byte[] clientSk = new byte[KeyExchange.PUBLICKEYBYTES];

        keyExchangeNative.cryptoKxKeypair(serverPk, serverSk);
        keyExchangeNative.cryptoKxKeypair(clientPk, clientSk);

        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxServerSessionKeys(new byte[KeyExchange.SESSIONKEYBYTES - 1], tx, serverPk, serverSk, clientPk));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxServerSessionKeys(new byte[KeyExchange.SESSIONKEYBYTES + 1], tx, serverPk, serverSk, clientPk));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxServerSessionKeys(rx, new byte[KeyExchange.SESSIONKEYBYTES - 1], serverPk, serverSk, clientPk));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxServerSessionKeys(rx, new byte[KeyExchange.SESSIONKEYBYTES + 1], serverPk, serverSk, clientPk));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxServerSessionKeys(rx, tx, new byte[KeyExchange.PUBLICKEYBYTES - 1], serverSk, clientPk));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxServerSessionKeys(rx, tx, new byte[KeyExchange.PUBLICKEYBYTES + 1], serverSk, clientPk));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxServerSessionKeys(rx, tx, serverPk, new byte[KeyExchange.SECRETKEYBYTES - 1], clientPk));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxServerSessionKeys(rx, tx, serverPk, new byte[KeyExchange.SECRETKEYBYTES + 1], clientPk));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxServerSessionKeys(rx, tx, serverPk, serverSk, new byte[KeyExchange.PUBLICKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> keyExchangeNative.cryptoKxServerSessionKeys(rx, tx, serverPk, serverSk, new byte[KeyExchange.PUBLICKEYBYTES + 1]));
    }
}
