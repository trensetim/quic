package com.timtrense.quic.impl;

import org.junit.Test;

import java.nio.ByteBuffer;

import static org.junit.Assert.assertEquals;

/**
 * @see HkdfUtil
 */
public class HkdfUtilTest {

    @Test
    public void label_quic_hp_correctlyEncoded() {
        String decodedLabel = String.valueOf(
                HkdfUtil.QUIC_LABEL_ENCODING_CHARSET.decode(
                        ByteBuffer.wrap(
                                HkdfUtil.LABEL_QUIC_HP
                        )
                )
        );
        assertEquals("quic hp", decodedLabel);
    }

    @Test
    public void label_quic_iv_correctlyEncoded() {
        String decodedLabel = String.valueOf(
                HkdfUtil.QUIC_LABEL_ENCODING_CHARSET.decode(
                        ByteBuffer.wrap(
                                HkdfUtil.LABEL_QUIC_IV
                        )
                )
        );
        assertEquals("quic iv", decodedLabel);
    }

    @Test
    public void label_quic_key_correctlyEncoded() {
        String decodedLabel = String.valueOf(
                HkdfUtil.QUIC_LABEL_ENCODING_CHARSET.decode(
                        ByteBuffer.wrap(
                                HkdfUtil.LABEL_QUIC_KEY
                        )
                )
        );
        assertEquals("quic key", decodedLabel);
    }

    @Test
    public void label_quic_ku_correctlyEncoded() {
        String decodedLabel = String.valueOf(
                HkdfUtil.QUIC_LABEL_ENCODING_CHARSET.decode(
                        ByteBuffer.wrap(
                                HkdfUtil.LABEL_QUIC_KU
                        )
                )
        );
        assertEquals("quic ku", decodedLabel);
    }

    @Test
    public void label_client_in_correctlyEncoded() {
        String decodedLabel = String.valueOf(
                HkdfUtil.QUIC_LABEL_ENCODING_CHARSET.decode(
                        ByteBuffer.wrap(
                                HkdfUtil.LABEL_CLIENT_IN
                        )
                )
        );
        assertEquals("client in", decodedLabel);
    }

    @Test
    public void label_server_in_correctlyEncoded() {
        String decodedLabel = String.valueOf(
                HkdfUtil.QUIC_LABEL_ENCODING_CHARSET.decode(
                        ByteBuffer.wrap(
                                HkdfUtil.LABEL_SERVER_IN
                        )
                )
        );
        assertEquals("server in", decodedLabel);
    }

}
