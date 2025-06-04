package com.goterl.lazysodium.utils;

import com.goterl.lazysodium.Sodium;

/**
 * Static access to a usable {@link Base64Facade}
 */
public final class Base64FacadeHolder {
    private Base64FacadeHolder() {
    }

    /**
     * Get a usable {@link Base64Facade} implementation.
     */
    @SuppressWarnings("removal")
    public static Base64Facade getBase64Facade() {
        if (Sodium.base64Facade == null) {
            throw new IllegalStateException(
                    "Sodium.base64Facade not initialised. " +
                            "Call LazySodiumJava() or LazySodiumAndroid().");
        }
        return Sodium.base64Facade;
    }
}
