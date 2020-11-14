package com.timtrense.quic.impl;

import at.favre.lib.crypto.HKDF;
import com.timtrense.quic.ConnectionId;
import lombok.NonNull;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * Utility functions for working with {@link HKDF}, relevant for QUIC or its embedding TLS 1.3
 *
 * @author Tim Trense
 */
public class HkdfUtil {

    /**
     * the charset used by QUIC Spec to encode the HKDF labels
     *
     * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.1">QUIC Spec-TLS/Section 5.1</a>
     */
    public static final Charset QUIC_LABEL_ENCODING_CHARSET = US_ASCII;

    /**
     * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.8">QUIC Spec-TLS/Section 5.8</a>
     */
    public static final byte[] QUIC_SECRET_KEY_SECRET = new byte[]{
            (byte) 0x8b, (byte) 0x0d, (byte) 0x37, (byte) 0xeb, (byte) 0x85, (byte) 0x35, (byte) 0x02, (byte) 0x2e,
            (byte) 0xbc, (byte) 0x8d, (byte) 0x76, (byte) 0xa2, (byte) 0x07, (byte) 0xd8, (byte) 0x0d, (byte) 0xf2,
            (byte) 0x26, (byte) 0x46, (byte) 0xec, (byte) 0x06, (byte) 0xdc, (byte) 0x80, (byte) 0x96, (byte) 0x42,
            (byte) 0xc3, (byte) 0x0a, (byte) 0x8b, (byte) 0xaa, (byte) 0x2b, (byte) 0xaa, (byte) 0xff, (byte) 0x4c
    };

    /**
     * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.8">QUIC Spec-TLS/Section 5.8</a>
     */
    public static final byte[] QUIC_RETRY_SECRET_KEY = new byte[]{
            (byte) 0xcc, (byte) 0xce, (byte) 0x18, (byte) 0x7e, (byte) 0xd0, (byte) 0x9a, (byte) 0x09, (byte) 0xd0,
            (byte) 0x57, (byte) 0x28, (byte) 0x15, (byte) 0x5a, (byte) 0x6c, (byte) 0xb9, (byte) 0x6b, (byte) 0xe1
    };

    /**
     * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.8">QUIC Spec-TLS/Section 5.8</a>
     */
    public static final byte[] QUIC_RETRY_NONCE = new byte[]{
            (byte) 0xe5, (byte) 0x49, (byte) 0x30, (byte) 0xf9, (byte) 0x7f, (byte) 0x21, (byte) 0x36, (byte) 0xf0,
            (byte) 0x53, (byte) 0x0a, (byte) 0x8c, (byte) 0x1c
    };

    /**
     * The string "tls13 " (with that whitespace) encoded as {@link StandardCharsets#US_ASCII}
     */
    public static final byte[] TLS_1_3_PREFIX =
            new byte[]{(byte) 0x74, (byte) 0x6c, (byte) 0x73, (byte) 0x31, (byte) 0x33, (byte) 0x20};

    /**
     * The string "client in" (with that whitespace) encoded as {@link StandardCharsets#US_ASCII}
     */
    public static final byte[] LABEL_CLIENT_IN =
            new byte[]{(byte) 0x63, (byte) 0x6c, (byte) 0x69, (byte) 0x65,
                    (byte) 0x6e, (byte) 0x74, (byte) 0x20, (byte) 0x69, (byte) 0x6e};

    /**
     * The string "server in" (with that whitespace) encoded as {@link StandardCharsets#US_ASCII}
     */
    public static final byte[] LABEL_SERVER_IN =
            new byte[]{(byte) 0x73, (byte) 0x65, (byte) 0x72, (byte) 0x76,
                    (byte) 0x65, (byte) 0x72, (byte) 0x20, (byte) 0x69, (byte) 0x6e};

    /**
     * The string "quic hp" (with that whitespace) encoded as {@link StandardCharsets#US_ASCII}
     * hp = header protection
     */
    public static final byte[] LABEL_QUIC_HP =
            new byte[]{(byte) 0x71, (byte) 0x75, (byte) 0x69, (byte) 0x63, (byte) 0x20, (byte) 0x68, (byte) 0x70};

    /**
     * The string "quic iv" (with that whitespace) encoded as {@link StandardCharsets#US_ASCII}
     * iv = input vector
     */
    public static final byte[] LABEL_QUIC_IV =
            new byte[]{(byte) 0x71, (byte) 0x75, (byte) 0x69, (byte) 0x63, (byte) 0x20, (byte) 0x69, (byte) 0x76};

    /**
     * The string "quic key" (with that whitespace) encoded as {@link StandardCharsets#US_ASCII}
     */
    public static final byte[] LABEL_QUIC_KEY =
            new byte[]{(byte) 0x71, (byte) 0x75, (byte) 0x69, (byte) 0x63, (byte) 0x20,
                    (byte) 0x6b, (byte) 0x65, (byte) 0x79};

    /**
     * The string "quic ku" (with that whitespace) encoded as {@link StandardCharsets#US_ASCII}
     * ku = key update
     */
    public static final byte[] LABEL_QUIC_KU =
            new byte[]{(byte) 0x71, (byte) 0x75, (byte) 0x69, (byte) 0x63, (byte) 0x20,
                    (byte) 0x6b, (byte) 0x75};

    /**
     * calls {@link HKDF#expand(byte[], byte[], int)} with the label and context properly converted to the HKDF info
     *
     * @param hkdf   the {@link HKDF} to use
     * @param secret the secret to derive the key from
     * @param label  the label for the key schedule, not including the {@link #TLS_1_3_PREFIX}
     * @param length the length of the output keying material
     * @return the produced keying material
     * @see <a href="https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1">TLS 1.3/Section 7.1</a>
     */
    public static byte[] tlsExpandLabel(
            @NonNull HKDF hkdf,
            @NonNull byte[] secret,
            @NonNull byte[] label,
            byte[] context,
            int length) {
        byte[] tlsLabel = tlsCreateLabel(label, context, length);
        return hkdf.expand(secret, tlsLabel, length);
    }

    /**
     * creates the label for use with the HKDF-Expand-Label function
     * (which is implemented in {@link #tlsExpandLabel(HKDF, byte[], byte[], byte[], int)})
     *
     * @param label   the actual label to expand (mostly an {@link StandardCharsets#US_ASCII}-encoded text)
     * @param context the context label to expand (mostly an {@link StandardCharsets#US_ASCII}-encoded text)
     * @param length  the length that will be requested from the HKDF-Expand-Label function
     * @return the label to expand a secret with (actually the HKDF-Expand-parameter "info")
     */
    public static byte[] tlsCreateLabel(@NonNull byte[] label, byte[] context, int length) {
        if (context == null) {
            context = new byte[]{};
        }
        //  "Its encoding will include a two-byte
        //   actual length field prepended to the vector"
        // Quote from TLS-1.3-Spec https://www.rfc-editor.org/rfc/rfc8446.html#section-3.4

        ByteBuffer clientLabel = ByteBuffer.allocate(10 /* 2 short length
                + 1 length of label + 1 length of context + 6 TLS_1_3_PREFIX.length*/
                + label.length
                + context.length
        );
        clientLabel.putShort((short) length);
        clientLabel.put((byte) (TLS_1_3_PREFIX.length + label.length));
        clientLabel.put(TLS_1_3_PREFIX);
        clientLabel.put(label);
        clientLabel.put((byte) (context.length));
        clientLabel.put(context);
        return clientLabel.array();
    }

    // <editor-fold desc="Expand Label Functions">

    /**
     * Creates the label for the HKDF-Expand-Label function from
     * the connection id combined with {@link #LABEL_CLIENT_IN}
     *
     * @param connectionId the connection id to expand
     * @return the expanded label
     */
    public static byte[] expandClientInLabel(@NonNull ConnectionId connectionId) {
        return tlsCreateLabel(LABEL_CLIENT_IN, null, (256 / 8) /*sha 256 byte length*/);
    }

    /**
     * Creates the label for the HKDF-Expand-Label function from
     * the connection id combined with {@link #LABEL_SERVER_IN}
     *
     * @param connectionId the connection id to expand
     * @return the expanded label
     */
    public static byte[] expandServerInLabel(@NonNull ConnectionId connectionId) {
        return tlsCreateLabel(LABEL_SERVER_IN, null, (256 / 8) /*sha 256 byte length*/);
    }

    /**
     * Creates the label for the HKDF-Expand-Label function from
     * the connection id combined with {@link #LABEL_QUIC_KEY}
     *
     * @param connectionId the connection id to expand
     * @return the expanded label
     */
    public static byte[] expandQuicKeyLabel(@NonNull ConnectionId connectionId) {
        // see https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.8 for reason for length
        return tlsCreateLabel(LABEL_QUIC_KEY, null, (128 / 8));
    }

    /**
     * Creates the label for the HKDF-Expand-Label function from
     * the connection id combined with {@link #LABEL_QUIC_IV}
     *
     * @param connectionId the connection id to expand
     * @return the expanded label
     */
    public static byte[] expandQuicIvLabel(@NonNull ConnectionId connectionId) {
        // see https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.8 for reason for length
        return tlsCreateLabel(LABEL_QUIC_IV, null, (96 / 8));
    }

    /**
     * Creates the label for the HKDF-Expand-Label function from
     * the connection id combined with {@link #LABEL_QUIC_HP}
     *
     * @param connectionId the connection id to expand
     * @return the expanded label
     */
    public static byte[] expandQuicHpLabel(@NonNull ConnectionId connectionId) {
        // quic header protection is always 16 bytes
        return tlsCreateLabel(LABEL_QUIC_HP, null, 16);
    }

    // </editor-fold>
}
