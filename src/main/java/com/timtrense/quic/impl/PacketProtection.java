package com.timtrense.quic.impl;

import lombok.NonNull;

/**
 * This interface implements the most high level encryption API for protecting packets with TLS 1.3 .
 *
 * @author Tim Trense
 */
public interface PacketProtection {

    /**
     * Computes the header protection mask
     *
     * @param sample the initial keying material, sampled bytes from the ciphertext
     * @param offset offset within the given byte-array to start reading the ikm from
     * @param length length of the ikm
     * @return the header protection mask
     */
    byte[] deriveHeaderProtectionMask( @NonNull byte[] sample, int offset, int length );

    /**
     * forwards {@link #deriveHeaderProtectionMask(byte[], int, int)} with offset=0 and length=sample.length.
     *
     * @param sample the initial keying material, sampled bytes from the ciphertext
     * @return the header protection mask
     */
    default byte[] deriveHeaderProtectionMask( @NonNull byte[] sample ) {
        return deriveHeaderProtectionMask( sample, 0, sample.length );
    }
}
