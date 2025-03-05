package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.Scrypt;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class ScryptTest extends BaseTest {

    private final String PASSWORD = "Password123456!!!!@@";
    private final byte[] PASSWORD_BYTES = PASSWORD.getBytes(StandardCharsets.UTF_8);
    private Scrypt.Lazy scryptLazy;

    @BeforeAll
    public void before() {
        scryptLazy = lazySodium;
    }

    @Test
    public void scryptHash() throws SodiumException {
        byte[] salt = new byte[LazySodium.longToInt(Scrypt.SCRYPTSALSA208SHA256_SALT_BYTES)];
        String scryptHash = scryptLazy.cryptoPwHashScryptSalsa208Sha256(
                PASSWORD,
                300L, // This can be anything up to Constants.SIZE_MAX
                salt,
                Scrypt.SCRYPTSALSA208SHA256_OPSLIMIT_MIN,
                Scrypt.SCRYPTSALSA208SHA256_MEMLIMIT_MIN
        );

        String hash = scryptLazy.cryptoPwHashScryptSalsa208Sha256Str(
                PASSWORD,
                Scrypt.SCRYPTSALSA208SHA256_OPSLIMIT_MIN,
                Scrypt.SCRYPTSALSA208SHA256_MEMLIMIT_MIN
        );

        boolean isCorrect = scryptLazy.cryptoPwHashScryptSalsa208Sha256StrVerify(hash, PASSWORD);


        assertTrue(isCorrect, "Minimum hashing failed.");
    }
}
