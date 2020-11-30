package com.timtrense.quic.tls;

import lombok.Data;

/**
 * <b>Diffie-Hellman Parameters</b>
 * <p/>
 * Diffie-Hellman [DH76] parameters for both clients and servers are
 * encoded in the opaque key_exchange field of a KeyShareEntry in a
 * KeyShare structure.  The opaque value contains the Diffie-Hellman
 * public value (Y = g^X mod p) for the specified group (see [RFC7919]
 * for group definitions) encoded as a big-endian integer and padded to
 * the left with zeros to the size of p in bytes.
 * <p/>
 * Note: For a given Diffie-Hellman group, the padding results in all
 * public keys having the same length.
 * <p/>
 * Peers MUST validate each other's public key Y by ensuring that
 * <pre>
 *     1 < Y < p-1
 * </pre>.
 * This check ensures that the remote peer is properly behaved
 * and isn't forcing the local system into a small subgroup.
 * <p/>
 * <b>ECDHE Parameters</b>
 * <p/>
 * ECDHE parameters for both clients and servers are encoded in the
 * opaque key_exchange field of a KeyShareEntry in a KeyShare structure.
 * <p/>
 * For secp256r1, secp384r1, and secp521r1, the contents are the
 * serialized value of the following struct:
 * <pre>
 * struct {
 *     uint8 legacy_form = 4;
 *     opaque X[coordinate_length];
 *     opaque Y[coordinate_length];
 * } UncompressedPointRepresentation;
 * </pre>
 * X and Y, respectively, are the binary representations of the x and y
 * values in network byte order.  There are no internal length markers,
 * so each number representation occupies as many octets as implied by
 * the curve parameters.  For P-256, this means that each of X and Y use
 * 32 octets, padded on the left by zeros if necessary.  For P-384, they
 * take 48 octets each.  For P-521, they take 66 octets each.
 * <p/>
 * For the curves secp256r1, secp384r1, and secp521r1, peers MUST
 * validate each other's public value Q by ensuring that the point is a
 * valid point on the elliptic curve.  The appropriate validation
 * procedures are defined in Section 4.3.7 of [ECDSA] and alternatively
 * in Section 5.6.2.3 of [KEYAGREEMENT].  This process consists of three
 * steps: (1) verify that Q is not the point at infinity (O), (2) verify
 * that for Q = (x, y) both integers x and y are in the correct
 * interval, and (3) ensure that (x, y) is a correct solution to the
 * elliptic curve equation.  For these curves, implementors do not need
 * to verify membership in the correct subgroup.
 * <p/>
 * For X25519 and X448, the contents of the public value are the byte
 * string inputs and outputs of the corresponding functions defined in
 * [RFC7748]: 32 bytes for X25519 and 56 bytes for X448.
 * <p/>
 * Note: Versions of TLS prior to 1.3 permitted point format
 * negotiation; TLS 1.3 removes this feature in favor of a single point
 * format for each curve.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.8.1">TLS 1.3 Spec/Section 4.2.8.1</a>
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.8.2">TLS 1.3 Spec/Section 4.2.8.2</a>
 */
@Data
public class UncompressedPointRepresentation {

    // uint8 legacy_form = 4

    private byte[] x;
    private byte[] y;

    /**
     * @return the length of the x-parameter
     */
    public int getXCoordinateLength() {
        return x.length;
    }

    /**
     * @return the length of the y-parameter
     */
    public int getYCoordinateLength() {
        return y.length;
    }

    /**
     * @return true if the x- and y-Values have the same length (which MUST be according to spec), false otherwise
     */
    public boolean isCoordinateLengthEqual() {
        return x.length == y.length;
    }
}
