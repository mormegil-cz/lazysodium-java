package com.goterl.lazysodium;

import com.goterl.lazysodium.interfaces.Random;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RandomTest extends BaseTest {
    private Random random;

    @BeforeAll
    public void before() {
        random = lazySodium;
    }

    @Test
    public void randomBytesRandom() {
        for (int i = 0; i < 10; ++i) {
            long value = random.randomBytesRandom();
            assertTrue(value >= 0 && value <= 0xffffffffL);
        }
    }

    @Test
    public void randomBytesUniform() {
        for (int i = 0; i < 10; ++i) {
            long value = random.randomBytesUniform(123);
            assertTrue(value >= 0 && value < 123);
        }
    }

    @Test
    public void randomBytesBufNative() {
        byte[] buf = new byte[50];
        random.randomBytesBuf(buf, buf.length - 1);
        assertEquals(0, buf[buf.length - 1]);
        assertTrue(countZeros(buf) < 30);
    }

    @Test
    public void rejectTooShortRandomBytesBuf() {
        byte[] buff = new byte[20];
        assertThrows(IllegalArgumentException.class, () -> random.randomBytesBuf(buff, -1));
        assertThrows(IllegalArgumentException.class, () -> random.randomBytesBuf(buff, buff.length + 1));
    }

    @Test
    public void randomBytesBufLazy() {
        byte[] buf = random.randomBytesBuf(50);
        assertNotNull(buf);
        assertEquals(50, buf.length);
        assertTrue(countZeros(buf) < 30);
    }

    @Test
    public void randomBytesDeterministicNative() {
        byte[] buf = new byte[10];
        random.randomBytesDeterministic(buf, buf.length - 1, new byte[Random.SEEDBYTES]);
        assertArrayEquals(new byte[]{(byte) 0xA1, (byte) 0x1F, (byte) 0x8F, (byte) 0x12, (byte) 0xD0, (byte) 0x87, (byte) 0x6F, (byte) 0x73, (byte) 0x6D, (byte) 0x0}, buf);
    }

    @Test
    public void rejectTooShortRandomBytesDeterministic() {
        byte[] buff = new byte[20];
        byte[] seed = new byte[Random.SEEDBYTES];
        assertThrows(IllegalArgumentException.class, () -> random.randomBytesDeterministic(buff, -1, seed));
        assertThrows(IllegalArgumentException.class, () -> random.randomBytesDeterministic(buff, buff.length + 1, seed));
    }

    @Test
    public void rejectInvalidSeed() {
        assertThrows(IllegalArgumentException.class, () -> random.randomBytesDeterministic(20, new byte[Random.SEEDBYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> random.randomBytesDeterministic(20, new byte[Random.SEEDBYTES + 1]));
    }

    @Test
    public void randomBytesDeterministicLazy() {
        byte[] buf = random.randomBytesDeterministic(10, new byte[Random.SEEDBYTES]);
        assertArrayEquals(new byte[]{(byte) 0xA1, (byte) 0x1F, (byte) 0x8F, (byte) 0x12, (byte) 0xD0, (byte) 0x87, (byte) 0x6F, (byte) 0x73, (byte) 0x6D, (byte) 0x2D}, buf);
    }

    @Test
    public void nonceNative() {
        byte[] buf = random.nonce(50);
        assertNotNull(buf);
        assertEquals(50, buf.length);
        assertTrue(countZeros(buf) < 30);
    }
}
