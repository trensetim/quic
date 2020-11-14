package com.timtrense.quic.impl;

import at.favre.lib.crypto.HKDF;
import lombok.NonNull;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import static java.nio.charset.StandardCharsets.ISO_8859_1;

/**
 * Utility functions for working with {@link HKDF}, relevant for QUIC or its embedding TLS 1.3
 *
 * @author Tim Trense
 */
public class HkdfUtil {

    /**
     * ISO-LATIN-1
     * the charset used by QUIC Spec to encode the HKDF labels
     */
    public static final Charset QUIC_LABEL_ENCODING_CHARSET = ISO_8859_1;

    /**
     * The string "tls13 " (with that whitespace) encoded as {@link StandardCharsets#ISO_8859_1}
     */
    public static final byte[] TLS_1_3_PREFIX =
            new byte[]{(byte) 0x74, (byte) 0x6c, (byte) 0x73, (byte) 0x31, (byte) 0x33, (byte) 0x20};

    /**
     * The string "client in" (with that whitespace) encoded as {@link StandardCharsets#ISO_8859_1}
     */
    public static final byte[] LABEL_CLIENT_IN =
            new byte[]{(byte) 0x63, (byte) 0x6c, (byte) 0x69, (byte) 0x65,
                    (byte) 0x6e, (byte) 0x74, (byte) 0x20, (byte) 0x69, (byte) 0x6e};

    /**
     * The string "server in" (with that whitespace) encoded as {@link StandardCharsets#ISO_8859_1}
     */
    public static final byte[] LABEL_SERVER_IN =
            new byte[]{(byte) 0x73, (byte) 0x65, (byte) 0x72, (byte) 0x76,
                    (byte) 0x65, (byte) 0x72, (byte) 0x20, (byte) 0x69, (byte) 0x6e};

    /**
     * The string "quic hp" (with that whitespace) encoded as {@link StandardCharsets#ISO_8859_1}
     * hp = header protection
     */
    public static final byte[] LABEL_QUIC_HP =
            new byte[]{(byte) 0x71, (byte) 0x75, (byte) 0x69, (byte) 0x63, (byte) 0x20, (byte) 0x68, (byte) 0x70};

    /**
     * The string "quic iv" (with that whitespace) encoded as {@link StandardCharsets#ISO_8859_1}
     * iv = input vector
     */
    public static final byte[] LABEL_QUIC_IV =
            new byte[]{(byte) 0x71, (byte) 0x75, (byte) 0x69, (byte) 0x63, (byte) 0x20, (byte) 0x69, (byte) 0x76};

    /**
     * The string "quic key" (with that whitespace) encoded as {@link StandardCharsets#ISO_8859_1}
     */
    public static final byte[] LABEL_QUIC_KEY =
            new byte[]{(byte) 0x71, (byte) 0x75, (byte) 0x69, (byte) 0x63, (byte) 0x20,
                    (byte) 0x6b, (byte) 0x65, (byte) 0x79};

    /**
     * The string "quic ku" (with that whitespace) encoded as {@link StandardCharsets#ISO_8859_1}
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
        return hkdf.expand(secret, clientLabel.array(), length);
    }
}
