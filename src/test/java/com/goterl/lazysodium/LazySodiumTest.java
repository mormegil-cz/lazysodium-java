package com.goterl.lazysodium;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class LazySodiumTest extends BaseTest {
    @Test
    public void toBinary() {
        assertArrayEquals(new byte[0], lazySodium.sodiumHex2Bin(""));
        assertArrayEquals(new byte[]{0x01, 0x02, (byte) 0xFE, (byte) 0x80, 0x7F}, lazySodium.sodiumHex2Bin("0102FE807F"));

        assertThrows(IllegalArgumentException.class, () -> lazySodium.sodiumHex2Bin("A"));
        assertThrows(IllegalArgumentException.class, () -> lazySodium.sodiumHex2Bin("333"));
        assertThrows(IllegalArgumentException.class, () -> lazySodium.sodiumHex2Bin("33AX"));
        assertThrows(IllegalArgumentException.class, () -> lazySodium.sodiumHex2Bin("01-23"));
    }
}
