package com.timtrense.quic.impl.base;

import at.favre.lib.crypto.HKDF;
import com.timtrense.quic.ConnectionId;
import com.timtrense.quic.EndpointRole;
import com.timtrense.quic.impl.HkdfUtil;
import com.timtrense.quic.impl.PacketProtection;
import com.timtrense.quic.impl.packets.InitialPacketImpl;
import lombok.Data;
import lombok.NonNull;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Data
public class InitialPacketProtectionImpl implements PacketProtection {

    /**
     * The initial salt is a meaningless truly random number defined by the protocol authors.
     *
     * @see <a href="https://github.com/quicwg/base-drafts/issues/4325">Github Issue of QUIC Working Group about the
     * arbitrary nature of that salt</a>
     * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.2">QUIC Spec-TLS/Section 5.2</a>
     */
    public static final byte[] INITIAL_SALT = new byte[]{
            (byte) 0xaf, (byte) 0xbf, (byte) 0xec, (byte) 0x28, (byte) 0x99, (byte) 0x93, (byte) 0xd2, (byte) 0x4c,
            (byte) 0x9e, (byte) 0x97, (byte) 0x86, (byte) 0xf1, (byte) 0x9c, (byte) 0x61, (byte) 0x11, (byte) 0xe0,
            (byte) 0x43, (byte) 0x90, (byte) 0xa8, (byte) 0x99
    };

    /**
     * The hash function for HKDF when deriving initial secrets and keys is SHA-256 [SHA].
     *
     * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.2">QUIC Spec-TLS/Section 5.2</a>
     */
    public static final HKDF INITIAL_DERIVATION_FUNCTION = HKDF.fromHmacSha256();

    private @NonNull EndpointRole endpointRole;
    private byte[] clientInitialSecret;
    private byte[] serverInitialSecret;
    private byte[] headerProtectionSecret;
    private Cipher headerProtectionCipher;

    /**
     * Generates the initial_secret as described by the pseudo-code of Section 5.2
     *
     * @param clientDestinationConnectionId the pseudo-code-parameter client_dst_connection_id
     * @return the pseudo-code-result initial_secret
     */
    public static byte[] extractInitialSecret(@NonNull ConnectionId clientDestinationConnectionId) {
        return INITIAL_DERIVATION_FUNCTION.extract(INITIAL_SALT, clientDestinationConnectionId.getValue());
    }

    /**
     * Generates the client_initial_secret as described by the pseudo-code of Section 5.2
     *
     * @param initialSecret the pseudo-code-parameter initial_secret
     * @return the pseudo-code-result client_initial_secret
     */
    public static byte[] expandInitialClientSecret(@NonNull byte[] initialSecret) {
        return HkdfUtil.tlsExpandLabel(INITIAL_DERIVATION_FUNCTION,
                initialSecret, HkdfUtil.LABEL_CLIENT_IN, null, (256 / 8) /*sha 256 byte length*/);
    }

    /**
     * Generates the server_initial_secret as described by the pseudo-code of Section 5.2
     *
     * @param initialSecret the pseudo-code-parameter initial_secret
     * @return the pseudo-code-result server_initial_secret
     */
    public static byte[] expandInitialServerSecret(@NonNull byte[] initialSecret) {
        return HkdfUtil.tlsExpandLabel(INITIAL_DERIVATION_FUNCTION,
                initialSecret, HkdfUtil.LABEL_SERVER_IN, null, (256 / 8) /*sha 256 byte length*/);
    }

    public static byte[] expandInitialHeaderProtection(@NonNull byte[] initialSecret) {
        return HkdfUtil.tlsExpandLabel(INITIAL_DERIVATION_FUNCTION,
                initialSecret, HkdfUtil.LABEL_QUIC_HP, null, 16 /* header protection mask byte length */);
    }

    public static byte[] expandInitialQuicKey(@NonNull byte[] initialSecret) {
        return HkdfUtil.tlsExpandLabel(INITIAL_DERIVATION_FUNCTION,
                initialSecret, HkdfUtil.LABEL_QUIC_KEY, null, (128 / 8));
    }

    public static byte[] expandInitialQuicIv(@NonNull byte[] initialSecret) {
        return HkdfUtil.tlsExpandLabel(INITIAL_DERIVATION_FUNCTION,
                initialSecret, HkdfUtil.LABEL_QUIC_IV, null, (96 / 8));
    }

    /**
     * Computes all initial secrets for server, client and header protection
     *
     * @param clientDestinationConnectionId the destination connection id sent by the client
     *                                      in the {@link InitialPacketImpl}
     * @throws NoSuchPaddingException   if the spec-required cipher could not be initialized
     * @throws NoSuchAlgorithmException if the spec-required cipher could not be initialized
     * @throws InvalidKeyException      if the spec-required cipher could not be initialized
     */
    public void initialize(@NonNull ConnectionId clientDestinationConnectionId)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] initialSecret = extractInitialSecret(clientDestinationConnectionId);
        clientInitialSecret = expandInitialClientSecret(initialSecret);
        serverInitialSecret = expandInitialServerSecret(initialSecret);
        headerProtectionSecret = expandInitialHeaderProtection(clientInitialSecret);
        // https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-5.4.3
        // "AEAD_AES_128_GCM and AEAD_AES_128_CCM use 128-bit AES [AES] in electronic code-book (ECB) mode."
        headerProtectionCipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(headerProtectionSecret, "AES");
        headerProtectionCipher.init(Cipher.ENCRYPT_MODE, keySpec);
    }

    @Override
    public byte[] deriveHeaderProtectionMask(@NonNull byte[] sample, int offset, int length) {
        if (headerProtectionCipher == null) {
            return null;
        }
        try {
            return headerProtectionCipher.doFinal(sample, offset, length);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }
}
