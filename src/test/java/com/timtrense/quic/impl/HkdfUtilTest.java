package com.timtrense.quic.impl;

import java.nio.ByteBuffer;

import at.favre.lib.crypto.HKDF;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * @see HkdfUtil
 */
public class HkdfUtilTest {

    @Test
    public void label_quicHp_correctlyEncoded() {
        String decodedLabel = String.valueOf(
                HkdfUtil.QUIC_LABEL_ENCODING_CHARSET.decode(
                        ByteBuffer.wrap(
                                HkdfUtil.LABEL_QUIC_HP
                        )
                )
        );
        assertEquals( "quic hp", decodedLabel );
    }

    @Test
    public void label_quicIv_correctlyEncoded() {
        String decodedLabel = String.valueOf(
                HkdfUtil.QUIC_LABEL_ENCODING_CHARSET.decode(
                        ByteBuffer.wrap(
                                HkdfUtil.LABEL_QUIC_IV
                        )
                )
        );
        assertEquals( "quic iv", decodedLabel );
    }

    @Test
    public void label_quicKey_correctlyEncoded() {
        String decodedLabel = String.valueOf(
                HkdfUtil.QUIC_LABEL_ENCODING_CHARSET.decode(
                        ByteBuffer.wrap(
                                HkdfUtil.LABEL_QUIC_KEY
                        )
                )
        );
        assertEquals( "quic key", decodedLabel );
    }

    @Test
    public void label_quicKu_correctlyEncoded() {
        String decodedLabel = String.valueOf(
                HkdfUtil.QUIC_LABEL_ENCODING_CHARSET.decode(
                        ByteBuffer.wrap(
                                HkdfUtil.LABEL_QUIC_KU
                        )
                )
        );
        assertEquals( "quic ku", decodedLabel );
    }

    @Test
    public void label_clientIn_correctlyEncoded() {
        String decodedLabel = String.valueOf(
                HkdfUtil.QUIC_LABEL_ENCODING_CHARSET.decode(
                        ByteBuffer.wrap(
                                HkdfUtil.LABEL_CLIENT_IN
                        )
                )
        );
        assertEquals( "client in", decodedLabel );
    }

    @Test
    public void label_serverIn_correctlyEncoded() {
        String decodedLabel = String.valueOf(
                HkdfUtil.QUIC_LABEL_ENCODING_CHARSET.decode(
                        ByteBuffer.wrap(
                                HkdfUtil.LABEL_SERVER_IN
                        )
                )
        );
        assertEquals( "server in", decodedLabel );
    }

    @Test
    public void label_retrySecret_canBeDerivedFromSecretKeySecret() {
        // see https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.8
        byte[] expanded = HkdfUtil.tlsExpandLabel(
                HKDF.fromHmacSha256(), /*todo: is that hash correct?*/
                HkdfUtil.QUIC_SECRET_KEY_SECRET, HkdfUtil.LABEL_QUIC_KEY, null, ( 128 / 8 ) );
        assertArrayEquals( HkdfUtil.QUIC_RETRY_SECRET_KEY, expanded );
    }

    @Test
    public void label_retryNone_canBeDerivedFromSecretKeySecret() {
        // see https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.8
        byte[] expanded = HkdfUtil.tlsExpandLabel(
                HKDF.fromHmacSha256(), /*todo: is that hash correct?*/
                HkdfUtil.QUIC_SECRET_KEY_SECRET, HkdfUtil.LABEL_QUIC_IV, null, ( 96 / 8 ) );
        assertArrayEquals( HkdfUtil.QUIC_RETRY_NONCE, expanded );
    }

}
