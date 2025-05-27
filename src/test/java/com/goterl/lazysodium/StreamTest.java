/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.interfaces.Stream;
import com.goterl.lazysodium.interfaces.StreamJava;
import com.goterl.lazysodium.utils.Key;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class StreamTest extends BaseTest {

    private static final String message1 = "A top secret message.";

    private StreamJava.Lazy streamLazy;
    private StreamJava.Native streamNative;

    @BeforeAll
    public void before() {
        streamLazy = lazySodium;
        streamNative = lazySodium;
    }

    @Test
    public void javaXChaCha20() {
        byte[] nonce = lazySodium.nonce(StreamJava.XCHACHA20_NONCEBYTES);
        Key key = streamLazy.cryptoStreamKeygen(StreamJava.Method.XCHACHA20);
        String cipher = streamLazy.cryptoStreamXor(message1, nonce, key, StreamJava.Method.XCHACHA20);
        String finalMsg = streamLazy.cryptoStreamXorDecrypt(cipher, nonce, key, StreamJava.Method.XCHACHA20);

        assertEquals(message1, finalMsg);
    }

    @Test
    public void javaSalsa2012() {
        byte[] nonce = lazySodium.nonce(StreamJava.SALSA2012_NONCEBYTES);
        Key key = streamLazy.cryptoStreamKeygen(StreamJava.Method.SALSA20_12);
        String cipher = streamLazy.cryptoStreamXor(message1, nonce, key, StreamJava.Method.SALSA20_12);
        String finalMsg = streamLazy.cryptoStreamXorDecrypt(cipher, nonce, key, StreamJava.Method.SALSA20_12);

        assertEquals(message1, finalMsg);
    }

    @Test
    public void javaSalsa208() {
        byte[] nonce = lazySodium.nonce(StreamJava.SALSA208_NONCEBYTES);
        Key key = streamLazy.cryptoStreamKeygen(StreamJava.Method.SALSA20_8);
        String cipher = streamLazy.cryptoStreamXor(message1, nonce, key, StreamJava.Method.SALSA20_8);
        String finalMsg = streamLazy.cryptoStreamXorDecrypt(cipher, nonce, key, StreamJava.Method.SALSA20_8);

        assertEquals(message1, finalMsg);
    }

    @Test
    public void chacha20() {
        byte[] c = new byte[32];
        int cLen = c.length;
        byte[] nonce = lazySodium.nonce(Stream.CHACHA20_NONCEBYTES);
        byte[] key = "RANDOM_KEY_OF_32_BYTES_LENGTH121".getBytes();

        lazySodium.cryptoStreamChaCha20(c, cLen, nonce, key);

        // Encrypt
        byte[] mBytes = message1.getBytes();
        byte[] cipher = new byte[mBytes.length];
        lazySodium.cryptoStreamChaCha20Xor(cipher, mBytes, mBytes.length, nonce, key);

        // Decrypt
        byte[] result = new byte[mBytes.length];
        lazySodium.cryptoStreamChaCha20Xor(result, cipher, cipher.length, nonce, key);

        assertEquals(message1, lazySodium.str(result));
    }

    @Test
    public void lazyChacha20() {
        byte[] nonce = lazySodium.nonce(Stream.CHACHA20_NONCEBYTES);
        Key key = streamLazy.cryptoStreamKeygen(Stream.Method.CHACHA20);
        String cipher = streamLazy.cryptoStreamXor(message1, nonce, key, Stream.Method.CHACHA20);
        String finalMsg = streamLazy.cryptoStreamXorDecrypt(cipher, nonce, key, Stream.Method.CHACHA20);

        assertEquals(message1, finalMsg);
    }

    @Test
    public void lazyChacha20Ietf() {
        byte[] nonce = lazySodium.nonce(Stream.CHACHA20_IETF_NONCEBYTES);
        Key key = streamLazy.cryptoStreamKeygen(Stream.Method.CHACHA20_IETF);
        String cipher = streamLazy.cryptoStreamXor(message1, nonce, key, Stream.Method.CHACHA20_IETF);
        String finalMsg = streamLazy.cryptoStreamXorDecrypt(cipher, nonce, key, Stream.Method.CHACHA20_IETF);

        assertEquals(message1, finalMsg);
    }

    @Test
    public void lazySalsa20() {
        String message = "Hello";

        byte[] nonce = lazySodium.nonce(Stream.SALSA20_NONCEBYTES);
        Key key = streamLazy.cryptoStreamKeygen(Stream.Method.SALSA20);
        String cipher = streamLazy.cryptoStreamXor(message, nonce, key, Stream.Method.SALSA20);
        String finalMsg = streamLazy.cryptoStreamXorDecrypt(cipher, nonce, key, Stream.Method.SALSA20);

        assertEquals(message, finalMsg);
    }

    @Test
    public void lazyXSalsa20() {
        byte[] nonce = lazySodium.nonce(Stream.XSALSA20_NONCEBYTES);
        Key key = streamLazy.cryptoStreamKeygen(Stream.Method.XSALSA20);
        String cipher = streamLazy.cryptoStreamXor(message1, nonce, key, Stream.Method.XSALSA20);
        String finalMsg = streamLazy.cryptoStreamXorDecrypt(cipher, nonce, key, Stream.Method.XSALSA20);

        assertEquals(message1, finalMsg);
    }

    @Test
    public void lazyDefault() {
        byte[] nonce = lazySodium.nonce(Stream.XSALSA20_NONCEBYTES);
        Key key = streamLazy.cryptoStreamKeygen((Stream.Method) null);
        String cipher = streamLazy.cryptoStreamXor(message1, nonce, key, (Stream.Method) null);
        String finalMsg = streamLazy.cryptoStreamXorDecrypt(cipher, nonce, key, (Stream.Method) null);

        assertEquals(message1, finalMsg);
    }

    @Test
    @SuppressWarnings("removal") // yep, we know
    public void cryptoStream() {
        byte[] nonce = lazySodium.nonce(Stream.XSALSA20_NONCEBYTES);
        Key key = streamLazy.cryptoStreamKeygen((Stream.Method) null);
        byte[] stream1 = streamLazy.cryptoStream(nonce, key, (Stream.Method) null);
        byte[] stream2 = streamLazy.cryptoStream(nonce, key, (Stream.Method) null);
        assertArrayEquals(stream1, stream2);
    }

    @Test
    public void cryptoStreamChaCha20KeygenChecks() {
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20Keygen(new byte[Stream.CHACHA20_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20Keygen(new byte[Stream.CHACHA20_KEYBYTES + 1]));
    }

    @Test
    public void cryptoStreamChaCha20IetfKeygenChecks() {
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20IetfKeygen(new byte[Stream.CHACHA20_IETF_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20IetfKeygen(new byte[Stream.CHACHA20_IETF_KEYBYTES + 1]));
    }

    @Test
    public void cryptoStreamSalsa20KeygenChecks() {
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20Keygen(new byte[Stream.SALSA20_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20Keygen(new byte[Stream.SALSA20_KEYBYTES + 1]));
    }

    @Test
    public void cryptoStreamXSalsa20KeygenChecks() {
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20Keygen(new byte[Stream.XSALSA20_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20Keygen(new byte[Stream.XSALSA20_KEYBYTES + 1]));
    }

    @Test
    public void cryptoStreamChaCha20Checks() {
        byte[] c = new byte[32];
        byte[] nonce = new byte[Stream.CHACHA20_NONCEBYTES];
        byte[] key = new byte[Stream.CHACHA20_KEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20(c, -1, nonce, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20(c, c.length + 1, nonce, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20(c, c.length, new byte[Stream.CHACHA20_NONCEBYTES - 1], key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20(c, c.length, new byte[Stream.CHACHA20_NONCEBYTES + 1], key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20(c, c.length, nonce, new byte[Stream.CHACHA20_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20(c, c.length, nonce, new byte[Stream.CHACHA20_KEYBYTES + 1]));
    }

    @Test
    public void cryptoStreamChaCha20IetfChecks() {
        byte[] c = new byte[32];
        byte[] nonce = new byte[Stream.CHACHA20_IETF_NONCEBYTES];
        byte[] key = new byte[Stream.CHACHA20_IETF_KEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20Ietf(c, -1, nonce, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20Ietf(c, c.length + 1, nonce, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20Ietf(c, c.length, new byte[Stream.CHACHA20_IETF_NONCEBYTES - 1], key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20Ietf(c, c.length, new byte[Stream.CHACHA20_IETF_NONCEBYTES + 1], key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20Ietf(c, c.length, nonce, new byte[Stream.CHACHA20_IETF_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20Ietf(c, c.length, nonce, new byte[Stream.CHACHA20_IETF_KEYBYTES + 1]));
    }

    @Test
    public void cryptoStreamSalsa20Checks() {
        byte[] c = new byte[32];
        byte[] nonce = new byte[Stream.SALSA20_NONCEBYTES];
        byte[] key = new byte[Stream.SALSA20_KEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20(c, -1, nonce, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20(c, c.length + 1, nonce, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20(c, c.length, new byte[Stream.SALSA20_NONCEBYTES - 1], key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20(c, c.length, new byte[Stream.SALSA20_NONCEBYTES + 1], key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20(c, c.length, nonce, new byte[Stream.SALSA20_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20(c, c.length, nonce, new byte[Stream.SALSA20_KEYBYTES + 1]));
    }

    @Test
    public void cryptoStreamXSalsa20Checks() {
        byte[] c = new byte[32];
        byte[] nonce = new byte[Stream.XSALSA20_NONCEBYTES];
        byte[] key = new byte[Stream.XSALSA20_KEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20(c, -1, nonce, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20(c, c.length + 1, nonce, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20(c, c.length, new byte[Stream.XSALSA20_NONCEBYTES - 1], key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20(c, c.length, new byte[Stream.XSALSA20_NONCEBYTES + 1], key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20(c, c.length, nonce, new byte[Stream.XSALSA20_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20(c, c.length, nonce, new byte[Stream.XSALSA20_KEYBYTES + 1]));
    }

    @Test
    public void cryptoStreamChaCha20XorChecks() {
        byte[] message = new byte[32];
        byte[] cipher = new byte[message.length];
        byte[] nonce = new byte[Stream.CHACHA20_NONCEBYTES];
        byte[] key = new byte[Stream.CHACHA20_KEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20Xor(cipher, message, -1, nonce, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20Xor(cipher, message, message.length + 1, nonce, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20Xor(cipher, message, message.length, new byte[Stream.CHACHA20_NONCEBYTES - 1], key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20Xor(cipher, message, message.length, new byte[Stream.CHACHA20_NONCEBYTES + 1], key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20Xor(cipher, message, message.length, nonce, new byte[Stream.CHACHA20_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20Xor(cipher, message, message.length, nonce, new byte[Stream.CHACHA20_KEYBYTES + 1]));
    }

    @Test
    public void cryptoStreamChaCha20IetfXorChecks() {
        byte[] message = new byte[32];
        byte[] cipher = new byte[message.length];
        byte[] nonce = new byte[Stream.CHACHA20_IETF_NONCEBYTES];
        byte[] key = new byte[Stream.CHACHA20_IETF_KEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20IetfXor(cipher, message, -1, nonce, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20IetfXor(cipher, message, message.length + 1, nonce, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20IetfXor(cipher, message, message.length, new byte[Stream.CHACHA20_IETF_NONCEBYTES - 1], key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20IetfXor(cipher, message, message.length, new byte[Stream.CHACHA20_IETF_NONCEBYTES + 1], key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20IetfXor(cipher, message, message.length, nonce, new byte[Stream.CHACHA20_IETF_NONCEBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20IetfXor(cipher, message, message.length, nonce, new byte[Stream.CHACHA20_IETF_KEYBYTES + 1]));
    }

    @Test
    public void cryptoStreamSalsa20XorChecks() {
        byte[] message = new byte[32];
        byte[] cipher = new byte[message.length];
        byte[] nonce = new byte[Stream.SALSA20_NONCEBYTES];
        byte[] key = new byte[Stream.SALSA20_KEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20Xor(cipher, message, -1, nonce, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20Xor(cipher, message, message.length + 1, nonce, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20Xor(cipher, message, message.length, new byte[Stream.SALSA20_NONCEBYTES - 1], key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20Xor(cipher, message, message.length, new byte[Stream.SALSA20_NONCEBYTES + 1], key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20Xor(cipher, message, message.length, nonce, new byte[Stream.SALSA20_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20Xor(cipher, message, message.length, nonce, new byte[Stream.SALSA20_KEYBYTES + 1]));
    }

    @Test
    public void cryptoStreamXSalsa20XorChecks() {
        byte[] message = new byte[32];
        byte[] cipher = new byte[message.length];
        byte[] nonce = new byte[Stream.XSALSA20_NONCEBYTES];
        byte[] key = new byte[Stream.XSALSA20_KEYBYTES];
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20Xor(cipher, message, -1, nonce, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20Xor(cipher, message, message.length + 1, nonce, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20Xor(cipher, message, message.length, new byte[Stream.XSALSA20_NONCEBYTES - 1], key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20Xor(cipher, message, message.length, new byte[Stream.XSALSA20_NONCEBYTES + 1], key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20Xor(cipher, message, message.length, nonce, new byte[Stream.XSALSA20_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20Xor(cipher, message, message.length, nonce, new byte[Stream.XSALSA20_KEYBYTES + 1]));
    }

    @Test
    public void cryptoStreamChaCha20XorIcChecks() {
        byte[] message = new byte[32];
        byte[] cipher = new byte[message.length];
        byte[] nonce = new byte[Stream.CHACHA20_NONCEBYTES];
        byte[] key = new byte[Stream.CHACHA20_KEYBYTES];
        long ic = 123456;
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20XorIc(cipher, message, -1, nonce, ic, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20XorIc(cipher, message, message.length + 1, nonce, ic, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20XorIc(cipher, message, message.length, new byte[Stream.CHACHA20_NONCEBYTES - 1], ic, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20XorIc(cipher, message, message.length, new byte[Stream.CHACHA20_NONCEBYTES + 1], ic, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20XorIc(cipher, message, message.length, nonce, ic, new byte[Stream.CHACHA20_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20XorIc(cipher, message, message.length, nonce, ic, new byte[Stream.CHACHA20_KEYBYTES + 1]));
    }

    @Test
    public void cryptoStreamChaCha20IetfXorIcChecks() {
        byte[] message = new byte[32];
        byte[] cipher = new byte[message.length];
        byte[] nonce = new byte[Stream.CHACHA20_IETF_NONCEBYTES];
        byte[] key = new byte[Stream.CHACHA20_IETF_KEYBYTES];
        long ic = 123456;
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20IetfXorIc(cipher, message, -1, nonce, ic, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20IetfXorIc(cipher, message, message.length + 1, nonce, ic, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20IetfXorIc(cipher, message, message.length, new byte[Stream.CHACHA20_IETF_NONCEBYTES - 1], ic, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20IetfXorIc(cipher, message, message.length, new byte[Stream.CHACHA20_IETF_NONCEBYTES + 1], ic, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20IetfXorIc(cipher, message, message.length, nonce, ic, new byte[Stream.CHACHA20_IETF_NONCEBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamChaCha20IetfXorIc(cipher, message, message.length, nonce, ic, new byte[Stream.CHACHA20_IETF_KEYBYTES + 1]));
    }

    @Test
    public void cryptoStreamSalsa20XorIcChecks() {
        byte[] message = new byte[32];
        byte[] cipher = new byte[message.length];
        byte[] nonce = new byte[Stream.SALSA20_NONCEBYTES];
        byte[] key = new byte[Stream.SALSA20_KEYBYTES];
        long ic = 123456;
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20XorIc(cipher, message, -1, nonce, ic, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20XorIc(cipher, message, message.length + 1, nonce, ic, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20XorIc(cipher, message, message.length, new byte[Stream.SALSA20_NONCEBYTES - 1], ic, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20XorIc(cipher, message, message.length, new byte[Stream.SALSA20_NONCEBYTES + 1], ic, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20XorIc(cipher, message, message.length, nonce, ic, new byte[Stream.SALSA20_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamSalsa20XorIc(cipher, message, message.length, nonce, ic, new byte[Stream.SALSA20_KEYBYTES + 1]));
    }

    @Test
    public void cryptoStreamXSalsa20XorIcChecks() {
        byte[] message = new byte[32];
        byte[] cipher = new byte[message.length];
        byte[] nonce = new byte[Stream.XSALSA20_NONCEBYTES];
        byte[] key = new byte[Stream.XSALSA20_KEYBYTES];
        long ic = 123456;
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20XorIc(cipher, message, -1, nonce, ic, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20XorIc(cipher, message, message.length + 1, nonce, ic, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20XorIc(cipher, message, message.length, new byte[Stream.XSALSA20_NONCEBYTES - 1], ic, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20XorIc(cipher, message, message.length, new byte[Stream.XSALSA20_NONCEBYTES + 1], ic, key));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20XorIc(cipher, message, message.length, nonce, ic, new byte[Stream.XSALSA20_KEYBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> streamNative.cryptoStreamXSalsa20XorIc(cipher, message, message.length, nonce, ic, new byte[Stream.XSALSA20_KEYBYTES + 1]));
    }


}
