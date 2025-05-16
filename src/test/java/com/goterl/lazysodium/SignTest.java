/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.Sign;
import com.goterl.lazysodium.utils.Key;
import com.goterl.lazysodium.utils.KeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SignTest extends BaseTest {

    private Sign.Lazy cryptoSignLazy;
    private Sign.Native cryptoSignNative;

    @BeforeAll
    public void before() {
        cryptoSignLazy = lazySodium;
        cryptoSignNative = lazySodium;
    }

    @Test
    public void generateKeyPair() throws SodiumException {
        KeyPair keys = cryptoSignLazy.cryptoSignKeypair();
        assertNotNull(keys);
    }

    @Test
    public void generateDeterministicPublicKeyPair() throws SodiumException {
        byte[] seed = new byte[Sign.SEEDBYTES];
        KeyPair keys = cryptoSignLazy.cryptoSignSeedKeypair(seed);
        KeyPair keys2 = cryptoSignLazy.cryptoSignSeedKeypair(seed);

        assertEquals(keys, keys2);
    }

    @Test
    public void generateDeterministicSecretKeyPair() throws SodiumException {
        byte[] seed = new byte[Sign.SEEDBYTES];
        KeyPair keys = cryptoSignLazy.cryptoSignSeedKeypair(seed);
        KeyPair keys2 = cryptoSignLazy.cryptoSignSeedKeypair(seed);

        assertEquals(keys, keys2);
    }


    @Test
    public void signMessage() throws SodiumException {
        String message = "This should get signed";

        KeyPair keyPair = cryptoSignLazy.cryptoSignKeypair();
        String signed = cryptoSignLazy.cryptoSign(message, keyPair.getSecretKey());

        // Now we can verify the signed message.
        String resultingMessage = cryptoSignLazy.cryptoSignOpen(signed, keyPair.getPublicKey());

        assertNotNull(resultingMessage);
    }


    @Test
    public void signDetached() throws SodiumException {
        String message = "sign this please";
        KeyPair keyPair = lazySodium.cryptoSignKeypair();

        String signature = lazySodium.cryptoSignDetached(message, keyPair.getSecretKey());
        boolean result = lazySodium.cryptoSignVerifyDetached(signature, message, keyPair.getPublicKey());

        assertTrue(result);
    }

    @Test
    public void convertEd25519ToCurve25519() throws SodiumException {
        Key publicKey = Key.fromHexString("0ae5c84877c9c534ffbb1f854550895a25a9ded6bd6b8a9035f38b9e03a0dfe2");
        Key secretKey = Key.fromHexString("0ae5c84877c9c534ffbb1f854550895a25a9ded6bd6b8a9035f38b9e03a0dfe20ae5c84877c9c534ffbb1f854550895a25a9ded6bd6b8a9035f38b9e03a0dfe2");
        KeyPair ed25519KeyPair = new KeyPair(publicKey, secretKey);

        KeyPair curve25519KeyPair = lazySodium.convertKeyPairEd25519ToCurve25519(ed25519KeyPair);

        assertEquals(
                "4c261ac83d4ffec2fd3f3d3e7082c5c18e2d5e144dae343069f48207edcdc43a",
                curve25519KeyPair.getPublicKey().getAsHexString().toLowerCase()
        );
        assertEquals(
                "588c6bcb80ebcbca68c0d039faeac79c0d0abc3f6078f23900760035ff9d0459",
                curve25519KeyPair.getSecretKey().getAsHexString().toLowerCase()
        );
    }

    @Test
    public void cryptoSignEd25519SkToSeed() throws SodiumException {
        byte[] seed = lazySodium.randomBytesBuf(Sign.ED25519_SEEDBYTES);
        KeyPair ed5519KeyPair = lazySodium.cryptoSignSeedKeypair(seed);
        byte[] result = lazySodium.cryptoSignEd25519SkToSeed(ed5519KeyPair.getSecretKey());
        assertEquals(LazySodium.toHex(seed), LazySodium.toHex(result));
    }

    @Test
    public void cryptoSignSecretKeyPair() throws SodiumException {
        KeyPair keys = lazySodium.cryptoSignKeypair();
        KeyPair extracted = lazySodium.cryptoSignSecretKeyPair(keys.getSecretKey());
        assertEquals(keys.getSecretKey().getAsHexString(), extracted.getSecretKey().getAsHexString());
        assertEquals(keys.getPublicKey().getAsHexString(), extracted.getPublicKey().getAsHexString());
    }


    @Test
    public void signLongMessage() throws SodiumException {
        String message = "This should get signed, This should get signed, " +
                "This should get signed, This should get signed, This should get signed" +
                "This should get signed, This should get signed, " +
                "This should get signed, This should get signed, This should get signed" +
                "This should get signed, This should get signed, " +
                "This should get signed, This should get signed, This should get signed" +
                "This should get signed, This should get signed, " +
                "This should get signed, This should get signed, This should get signed";
        byte[] messageBytes = message.getBytes();

        KeyPair keyPair = cryptoSignLazy.cryptoSignKeypair();
        Key sk = keyPair.getSecretKey();
        Key pk = keyPair.getPublicKey();


        Sign.StateCryptoSign state = new Sign.StateCryptoSign();
        boolean inited = lazySodium.cryptoSignInit(state);
        assertTrue(inited, "cryptoSignInit not started successfully.");

        boolean update1 = lazySodium.cryptoSignUpdate(state, messageBytes, messageBytes.length);
        assertTrue(update1, "First cryptoSignUpdate did not work.");

        boolean update2 = lazySodium.cryptoSignUpdate(state, messageBytes, messageBytes.length);
        assertTrue(update2, "Second cryptoSignUpdate did not work.");

        // Clone the state now as cryptoSignFinalCreate zeroes
        // all the values.
        Sign.StateCryptoSign clonedState = state.clone();

        byte[] signature = new byte[Sign.BYTES];
        boolean createdSignature = lazySodium.cryptoSignFinalCreate(state, signature, sk.getAsBytes());
        assertTrue(createdSignature, "cryptoSignFinalCreate unsuccessful");

        boolean verified = lazySodium.cryptoSignFinalVerify(clonedState, signature, pk.getAsBytes());
        assertTrue(verified, "cryptoSignFinalVerify did not work");

        signature[signature.length / 2] ^= 0x04;
        boolean verifiedWrongSig = lazySodium.cryptoSignFinalVerify(clonedState, signature, pk.getAsBytes());
        assertFalse(verifiedWrongSig, "cryptoSignFinalVerify succeeded with wrong signature");
    }

    @Test
    public void cryptoSignUpdateChecks() {
        Sign.StateCryptoSign state = new Sign.StateCryptoSign();
        assertTrue(cryptoSignNative.cryptoSignInit(state));
        byte[] buff = new byte[10];
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignUpdate(state, buff, -1));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignUpdate(state, buff, buff.length + 1));
    }

    @Test
    public void cryptoSignFinalCreateChecks() {
        Sign.StateCryptoSign state = new Sign.StateCryptoSign();
        assertTrue(cryptoSignNative.cryptoSignInit(state));
        byte[] sig = new byte[Sign.BYTES];
        byte[] sk = new byte[Sign.SECRETKEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignFinalCreate(state, new byte[Sign.BYTES - 1], sk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignFinalCreate(state, new byte[Sign.BYTES + 1], sk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignFinalCreate(state, sig, new byte[Sign.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignFinalCreate(state, sig, new byte[Sign.SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoSignFinalVerifyChecks() {
        Sign.StateCryptoSign state = new Sign.StateCryptoSign();
        assertTrue(cryptoSignNative.cryptoSignInit(state));
        byte[] sig = new byte[Sign.BYTES];
        byte[] pk = new byte[Sign.PUBLICKEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignFinalVerify(state, new byte[Sign.BYTES - 1], pk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignFinalVerify(state, new byte[Sign.BYTES + 1], pk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignFinalVerify(state, sig, new byte[Sign.PUBLICKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignFinalVerify(state, sig, new byte[Sign.PUBLICKEYBYTES + 1]));
    }

    @Test
    public void cryptoSignKeypairChecks() {
        byte[] pk = new byte[Sign.PUBLICKEYBYTES];
        byte[] sk = new byte[Sign.SECRETKEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignKeypair(new byte[Sign.PUBLICKEYBYTES - 1], sk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignKeypair(new byte[Sign.PUBLICKEYBYTES + 1], sk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignKeypair(pk, new byte[Sign.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignKeypair(pk, new byte[Sign.SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoSignSeedKeypairChecks() {
        byte[] pk = new byte[Sign.PUBLICKEYBYTES];
        byte[] sk = new byte[Sign.SECRETKEYBYTES];
        byte[] seed = new byte[Sign.SEEDBYTES];
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignSeedKeypair(new byte[Sign.PUBLICKEYBYTES - 1], sk, seed));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignSeedKeypair(new byte[Sign.PUBLICKEYBYTES + 1], sk, seed));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignSeedKeypair(pk, new byte[Sign.SECRETKEYBYTES - 1], seed));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignSeedKeypair(pk, new byte[Sign.SECRETKEYBYTES + 1], seed));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignSeedKeypair(pk, sk, new byte[Sign.SEEDBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignSeedKeypair(pk, sk, new byte[Sign.SEEDBYTES + 1]));
    }

    @Test
    public void cryptoSignChecks() {
        byte[] message = new byte[10];
        byte[] sk = new byte[Sign.SECRETKEYBYTES];
        byte[] signedMessage = new byte[message.length + Sign.BYTES];
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSign(new byte[signedMessage.length - 1], message, message.length, sk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSign(new byte[signedMessage.length + 1], message, message.length, sk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSign(signedMessage, message, -1, sk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSign(signedMessage, message, message.length + 1, sk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSign(signedMessage, message, message.length, new byte[Sign.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSign(signedMessage, message, message.length, new byte[Sign.SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoSignOpenChecks() {
        byte[] message = new byte[10];
        byte[] pk = new byte[Sign.PUBLICKEYBYTES];
        byte[] signedMessage = new byte[message.length + Sign.BYTES];
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignOpen(new byte[message.length - 1], signedMessage, signedMessage.length, pk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignOpen(new byte[message.length + 1], signedMessage, signedMessage.length, pk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignOpen(message, signedMessage, -1, pk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignOpen(message, signedMessage, signedMessage.length + 1, pk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignOpen(message, signedMessage, signedMessage.length, new byte[Sign.PUBLICKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignOpen(message, signedMessage, signedMessage.length, new byte[Sign.PUBLICKEYBYTES + 1]));
    }

    @Test
    public void cryptoSignDetachedChecks() {
        byte[] message = new byte[10];
        byte[] sk = new byte[Sign.SECRETKEYBYTES];
        byte[] sig = new byte[Sign.BYTES];
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignDetached(new byte[Sign.BYTES - 1], message, message.length, sk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignDetached(new byte[Sign.BYTES + 1], message, message.length, sk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignDetached(sig, message, -1, sk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignDetached(sig, message, message.length + 1, sk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignDetached(sig, message, message.length, new byte[Sign.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignDetached(sig, message, message.length, new byte[Sign.SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoSignVerifyDetachedChecks() {
        byte[] message = new byte[10];
        byte[] pk = new byte[Sign.PUBLICKEYBYTES];
        byte[] sig = new byte[Sign.BYTES];
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignVerifyDetached(new byte[Sign.BYTES - 1], message, message.length, pk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignVerifyDetached(new byte[Sign.BYTES + 1], message, message.length, pk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignVerifyDetached(sig, message, -1, pk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignVerifyDetached(sig, message, message.length + 1, pk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignVerifyDetached(sig, message, message.length, new byte[Sign.PUBLICKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignVerifyDetached(sig, message, message.length, new byte[Sign.PUBLICKEYBYTES + 1]));
    }


    @Test
    public void convertPublicKeyEd25519ToCurve25519Checks() {
        byte[] curve = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        byte[] ed = new byte[Sign.ED25519_PUBLICKEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.convertPublicKeyEd25519ToCurve25519(new byte[Sign.CURVE25519_PUBLICKEYBYTES - 1], ed));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.convertPublicKeyEd25519ToCurve25519(new byte[Sign.CURVE25519_PUBLICKEYBYTES + 1], ed));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.convertPublicKeyEd25519ToCurve25519(curve, new byte[Sign.ED25519_PUBLICKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.convertPublicKeyEd25519ToCurve25519(curve, new byte[Sign.ED25519_PUBLICKEYBYTES + 1]));
    }

    @Test
    public void convertSecretKeyEd25519ToCurve25519Checks() {
        byte[] curve = new byte[Sign.CURVE25519_SECRETKEYBYTES];
        byte[] ed = new byte[Sign.ED25519_SECRETKEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.convertSecretKeyEd25519ToCurve25519(new byte[Sign.CURVE25519_SECRETKEYBYTES - 1], ed));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.convertSecretKeyEd25519ToCurve25519(new byte[Sign.CURVE25519_SECRETKEYBYTES + 1], ed));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.convertSecretKeyEd25519ToCurve25519(curve, new byte[Sign.ED25519_SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.convertSecretKeyEd25519ToCurve25519(curve, new byte[Sign.ED25519_SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoSignEd25519SkToSeedChecks() {
        byte[] seed = new byte[Sign.ED25519_SEEDBYTES];
        byte[] sk = new byte[Sign.ED25519_SECRETKEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignEd25519SkToSeed(new byte[Sign.ED25519_SEEDBYTES - 1], sk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignEd25519SkToSeed(new byte[Sign.ED25519_SEEDBYTES + 1], sk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignEd25519SkToSeed(seed, new byte[Sign.ED25519_SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignEd25519SkToSeed(seed, new byte[Sign.ED25519_SECRETKEYBYTES + 1]));
    }

    @Test
    public void cryptoSignEd25519SkToPkChecks() {
        byte[] pk = new byte[Sign.PUBLICKEYBYTES];
        byte[] sk = new byte[Sign.SECRETKEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignEd25519SkToPk(new byte[Sign.PUBLICKEYBYTES - 1], sk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignEd25519SkToPk(new byte[Sign.PUBLICKEYBYTES + 1], sk));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignEd25519SkToPk(pk, new byte[Sign.SECRETKEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> cryptoSignNative.cryptoSignEd25519SkToPk(pk, new byte[Sign.SECRETKEYBYTES + 1]));
    }

}
