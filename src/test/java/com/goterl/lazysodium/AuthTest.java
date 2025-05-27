/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.Auth;
import com.goterl.lazysodium.utils.Key;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class AuthTest extends BaseTest {

    private Auth.Lazy authLazy;
    private Auth.Native authNative;

    @BeforeAll
    public void before() {
        authLazy = lazySodium;
        authNative = lazySodium;
    }

    @Test
    public void authKeygenAndVerify() throws SodiumException {
        String m = "A simple message.";

        Key key = authLazy.cryptoAuthKeygen();
        String tag = authLazy.cryptoAuth(m, key);

        boolean verification = authLazy.cryptoAuthVerify(tag, m, key);

        assertTrue(verification);
    }

    @Test
    public void auth256KeygenAndVerify() {
        String m = "A simple message.";

        Key k = authLazy.cryptoAuthHMACShaKeygen(Auth.Type.SHA256);
        String shaResult = authLazy.cryptoAuthHMACSha(Auth.Type.SHA256, m, k);
        boolean isTrue = authLazy.cryptoAuthHMACShaVerify(Auth.Type.SHA256, shaResult, m, k);
        assertTrue(isTrue);
    }

    @Test
    public void auth512KeygenAndVerify() {
        String m = "A simple message.";

        Key k = authLazy.cryptoAuthHMACShaKeygen(Auth.Type.SHA512);
        String shaResult = authLazy.cryptoAuthHMACSha(Auth.Type.SHA512, m, k);
        boolean isTrue = authLazy.cryptoAuthHMACShaVerify(Auth.Type.SHA512, shaResult, m, k);
        assertTrue(isTrue);
    }

    @Test
    public void auth512256KeygenAndVerify() {
        String m = "Follow us on twitter @terlacious";

        Key k = authLazy.cryptoAuthHMACShaKeygen(Auth.Type.SHA512256);
        String shaResult = authLazy.cryptoAuthHMACSha(Auth.Type.SHA512256, m, k);
        boolean isTrue = authLazy.cryptoAuthHMACShaVerify(Auth.Type.SHA512256, shaResult, m, k);
        assertTrue(isTrue);
    }

    @Test
    public void auth256StreamKeygenAndVerify() throws SodiumException {
        String m = "Terl is ";
        String m2 = "the best";

        Key k = authLazy.cryptoAuthHMACShaKeygen(Auth.Type.SHA256);
        Auth.StateHMAC256 state = new Auth.StateHMAC256();


        boolean res = authLazy.cryptoAuthHMACShaInit(state, k);
        if (!res) {
            fail("Could not initialise HMAC Sha.");
            return;
        }

        boolean res2 = authLazy.cryptoAuthHMACShaUpdate(state, m);
        if (!res2) {
            fail("Could not update HMAC Sha.");
            return;
        }

        boolean res3 = authLazy.cryptoAuthHMACShaUpdate(state, m2);
        if (!res3) {
            fail("Could not update HMAC Sha (part 2).");
            return;
        }

        String sha = authLazy.cryptoAuthHMACShaFinal(state);

        boolean isTrue = authLazy.cryptoAuthHMACShaVerify(Auth.Type.SHA256, sha, m + m2, k);
        assertTrue(isTrue);
    }


    @Test
    public void auth512StreamKeygenAndVerify() throws SodiumException {
        String m = "Lazysodium makes devs lazy";
        String m2 = " but don't tell your manager that!";

        Key k = authLazy.cryptoAuthHMACShaKeygen(Auth.Type.SHA512);
        Auth.StateHMAC512 state = new Auth.StateHMAC512();


        boolean res = authLazy.cryptoAuthHMACShaInit(state, k);
        if (!res) {
            fail("Could not initialise HMAC Sha.");
            return;
        }

        boolean res2 = authLazy.cryptoAuthHMACShaUpdate(state, m);
        if (!res2) {
            fail("Could not update HMAC Sha.");
            return;
        }

        boolean res3 = authLazy.cryptoAuthHMACShaUpdate(state, m2);
        if (!res3) {
            fail("Could not update HMAC Sha (part 2).");
            return;
        }

        String sha = authLazy.cryptoAuthHMACShaFinal(state);

        boolean isTrue = authLazy.cryptoAuthHMACShaVerify(Auth.Type.SHA512, sha, m + m2, k);
        assertTrue(isTrue);
    }


    @Test
    public void auth512256StreamKeygenAndVerify() throws SodiumException {
        String m = "A string that ";
        String m2 = "is sha512256 sha mac'd ";
        String m3 = "is super secure.";

        Key k = authLazy.cryptoAuthHMACShaKeygen(Auth.Type.SHA512256);
        Auth.StateHMAC512256 state = new Auth.StateHMAC512256();


        boolean res = authLazy.cryptoAuthHMACShaInit(state, k);
        boolean res2 = authLazy.cryptoAuthHMACShaUpdate(state, m);
        boolean res3 = authLazy.cryptoAuthHMACShaUpdate(state, m2);
        boolean res4 = authLazy.cryptoAuthHMACShaUpdate(state, m3);

        String sha = authLazy.cryptoAuthHMACShaFinal(state);

        boolean isTrue = authLazy.cryptoAuthHMACShaVerify(Auth.Type.SHA512256, sha, m + m2 + m3, k);
        assertTrue(isTrue);
    }

    @Test
    public void cryptoAuthChecks() {
        final byte[] tag = new byte[Auth.BYTES];
        final byte[] key = new byte[Auth.KEYBYTES];
        final byte[] in = new byte[50];

        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuth(new byte[Auth.BYTES - 1], in, in.length, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuth(new byte[Auth.BYTES + 1], in, in.length, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuth(tag, in, -1, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuth(tag, in, in.length + 1, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuth(tag, in, in.length, new byte[Auth.KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuth(tag, in, in.length, new byte[Auth.KEYBYTES + 1]));
    }

    @Test
    public void cryptoAuthVerifyChecks() {
        final byte[] tag = new byte[Auth.BYTES];
        final byte[] key = new byte[Auth.KEYBYTES];
        final byte[] in = new byte[50];

        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthVerify(new byte[Auth.BYTES - 1], in, in.length, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthVerify(new byte[Auth.BYTES + 1], in, in.length, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthVerify(tag, in, -1, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthVerify(tag, in, in.length + 1, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthVerify(tag, in, in.length, new byte[Auth.KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthVerify(tag, in, in.length, new byte[Auth.KEYBYTES + 1]));
    }

    @Test
    public void cryptoAuthKeygenChecks() {
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthKeygen(new byte[Auth.KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthKeygen(new byte[Auth.KEYBYTES + 1]));
    }

    @Test
    public void cryptoAuthHMACSha256KeygenChecks() {
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256Keygen(new byte[Auth.HMACSHA256_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256Keygen(new byte[Auth.HMACSHA256_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAuthHMACSha256Checks() {
        final byte[] hash = new byte[Auth.HMACSHA256_BYTES];
        final byte[] key = new byte[Auth.HMACSHA256_KEYBYTES];
        final byte[] in = new byte[50];

        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256(new byte[Auth.HMACSHA256_BYTES - 1], in, in.length, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256(new byte[Auth.HMACSHA256_BYTES + 1], in, in.length, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256(hash, in, -1, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256(hash, in, in.length + 1, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256(hash, in, in.length, new byte[Auth.HMACSHA256_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256(hash, in, in.length, new byte[Auth.HMACSHA256_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAuthHMACSha256VerifyChecks() {
        final byte[] hash = new byte[Auth.HMACSHA256_BYTES];
        final byte[] key = new byte[Auth.HMACSHA256_KEYBYTES];
        final byte[] in = new byte[50];

        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256Verify(new byte[Auth.HMACSHA256_BYTES - 1], in, in.length, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256Verify(new byte[Auth.HMACSHA256_BYTES + 1], in, in.length, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256Verify(hash, in, -1, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256Verify(hash, in, in.length + 1, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256Verify(hash, in, in.length, new byte[Auth.HMACSHA256_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256Verify(hash, in, in.length, new byte[Auth.HMACSHA256_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAuthHMACSha256InitChecks() {
        final Auth.StateHMAC256 state = new Auth.StateHMAC256();
        final byte[] key = new byte[20];

        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256Init(state, key, -1));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256Init(state, key, key.length + 1));
    }

    @Test
    public void cryptoAuthHMACSha256UpdateChecks() {
        final Auth.StateHMAC256 state = new Auth.StateHMAC256();
        final byte[] in = new byte[50];

        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256Update(state, in, -1));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256Update(state, in, in.length + 1));
    }

    @Test
    public void cryptoAuthHMACSha256FinalChecks() {
        final Auth.StateHMAC256 state = new Auth.StateHMAC256();
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256Final(state, new byte[Auth.HMACSHA256_BYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha256Final(state, new byte[Auth.HMACSHA256_BYTES + 1]));
    }

    @Test
    public void cryptoAuthHMACSha512KeygenChecks() {
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512Keygen(new byte[Auth.HMACSHA512_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512Keygen(new byte[Auth.HMACSHA512_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAuthHMACSha512Checks() {
        final byte[] hash = new byte[Auth.HMACSHA512_BYTES];
        final byte[] key = new byte[Auth.HMACSHA512_KEYBYTES];
        final byte[] in = new byte[50];

        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512(new byte[Auth.HMACSHA512_BYTES - 1], in, in.length, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512(new byte[Auth.HMACSHA512_BYTES + 1], in, in.length, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512(hash, in, -1, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512(hash, in, in.length + 1, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512(hash, in, in.length, new byte[Auth.HMACSHA512_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512(hash, in, in.length, new byte[Auth.HMACSHA512_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAuthHMACSha512VerifyChecks() {
        final byte[] hash = new byte[Auth.HMACSHA512_BYTES];
        final byte[] key = new byte[Auth.HMACSHA512_KEYBYTES];
        final byte[] in = new byte[50];

        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512Verify(new byte[Auth.HMACSHA512_BYTES - 1], in, in.length, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512Verify(new byte[Auth.HMACSHA512_BYTES + 1], in, in.length, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512Verify(hash, in, -1, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512Verify(hash, in, in.length + 1, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512Verify(hash, in, in.length, new byte[Auth.HMACSHA512_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512Verify(hash, in, in.length, new byte[Auth.HMACSHA512_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAuthHMACSha512InitChecks() {
        final Auth.StateHMAC512 state = new Auth.StateHMAC512();
        final byte[] key = new byte[20];

        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512Init(state, key, -1));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512Init(state, key, key.length + 1));
    }

    @Test
    public void cryptoAuthHMACSha512UpdateChecks() {
        final Auth.StateHMAC512 state = new Auth.StateHMAC512();
        final byte[] in = new byte[50];

        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512Update(state, in, -1));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512Update(state, in, in.length + 1));
    }

    @Test
    public void cryptoAuthHMACSha512FinalChecks() {
        final Auth.StateHMAC512 state = new Auth.StateHMAC512();
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512Final(state, new byte[Auth.HMACSHA512_BYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512Final(state, new byte[Auth.HMACSHA512_BYTES + 1]));
    }

    @Test
    public void cryptoAuthHMACSha512256KeygenChecks() {
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256Keygen(new byte[Auth.HMACSHA512256_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256Keygen(new byte[Auth.HMACSHA512256_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAuthHMACSha512256Checks() {
        final byte[] hash = new byte[Auth.HMACSHA512256_BYTES];
        final byte[] key = new byte[Auth.HMACSHA512256_KEYBYTES];
        final byte[] in = new byte[50];

        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256(new byte[Auth.HMACSHA512256_BYTES - 1], in, in.length, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256(new byte[Auth.HMACSHA512256_BYTES + 1], in, in.length, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256(hash, in, -1, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256(hash, in, in.length + 1, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256(hash, in, in.length, new byte[Auth.HMACSHA512256_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256(hash, in, in.length, new byte[Auth.HMACSHA512256_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAuthHMACSha512256VerifyChecks() {
        final byte[] hash = new byte[Auth.HMACSHA512256_BYTES];
        final byte[] key = new byte[Auth.HMACSHA512256_KEYBYTES];
        final byte[] in = new byte[50];

        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256Verify(new byte[Auth.HMACSHA512256_BYTES - 1], in, in.length, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256Verify(new byte[Auth.HMACSHA512256_BYTES + 1], in, in.length, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256Verify(hash, in, -1, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256Verify(hash, in, in.length + 1, key));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256Verify(hash, in, in.length, new byte[Auth.HMACSHA512256_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256Verify(hash, in, in.length, new byte[Auth.HMACSHA512256_KEYBYTES + 1]));
    }

    @Test
    public void cryptoAuthHMACSha512256InitChecks() {
        final Auth.StateHMAC512256 state = new Auth.StateHMAC512256();
        final byte[] key = new byte[20];

        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256Init(state, key, -1));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256Init(state, key, key.length + 1));
    }

    @Test
    public void cryptoAuthHMACSha512256UpdateChecks() {
        final Auth.StateHMAC512256 state = new Auth.StateHMAC512256();
        final byte[] in = new byte[50];

        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256Update(state, in, -1));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256Update(state, in, in.length + 1));
    }

    @Test
    public void cryptoAuthHMACSha512256FinalChecks() {
        final Auth.StateHMAC512256 state = new Auth.StateHMAC512256();
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256Final(state, new byte[Auth.HMACSHA512256_BYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> authNative.cryptoAuthHMACSha512256Final(state, new byte[Auth.HMACSHA512256_BYTES + 1]));
    }
}
