package com.timtrense.quic.impl.base;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.NoSuchPaddingException;

import org.junit.BeforeClass;
import org.junit.Test;

import com.timtrense.quic.ConnectionId;
import com.timtrense.quic.EndpointRole;
import com.timtrense.quic.VariableLengthInteger;
import com.timtrense.quic.impl.HkdfUtil;

import static org.junit.Assert.assertArrayEquals;

/**
 * @see InitialPacketProtectionImpl
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#appendix-A">QUIC Spec-TLS/Appendix A</a>
 */
public class InitialPacketProtectionImplTest {

    static ConnectionId clientConnectionId;

    @BeforeClass
    public static void setupClientConnectionId() {
        byte[] ccid = new byte[]{
                (byte)0x83, (byte)0x94, (byte)0xc8, (byte)0xf0,
                (byte)0x3e, (byte)0x51, (byte)0x57, (byte)0x08
        };
        clientConnectionId = new ConnectionIdImpl( ccid, VariableLengthInteger.ZERO );
    }

    // <editor-fold desc="Test Expand Labels">

    @Test
    public void expandClientInLabel_givenAppendixADefinedClientConnectionId_matchesSpecExample() {
        byte[] clientInLabel = HkdfUtil.expandClientInLabel( clientConnectionId );
        assertArrayEquals( new byte[]{
                (byte)0x00, (byte)0x20, (byte)0x0f, (byte)0x74, (byte)0x6c, (byte)0x73, (byte)0x31, (byte)0x33,
                (byte)0x20, (byte)0x63, (byte)0x6c, (byte)0x69, (byte)0x65, (byte)0x6e, (byte)0x74, (byte)0x20,
                (byte)0x69, (byte)0x6e, (byte)0x00
        }, clientInLabel );
    }

    @Test
    public void expandServerInLabel_givenAppendixADefinedClientConnectionId_matchesSpecExample() {
        byte[] serverInLabel = HkdfUtil.expandServerInLabel( clientConnectionId );
        assertArrayEquals( new byte[]{
                (byte)0x00, (byte)0x20, (byte)0x0f, (byte)0x74, (byte)0x6c, (byte)0x73, (byte)0x31, (byte)0x33,
                (byte)0x20, (byte)0x73, (byte)0x65, (byte)0x72, (byte)0x76, (byte)0x65, (byte)0x72, (byte)0x20,
                (byte)0x69, (byte)0x6e, (byte)0x00
        }, serverInLabel );
    }

    @Test
    public void expandQuicKeyLabel_givenAppendixADefinedClientConnectionId_matchesSpecExample() {
        byte[] quicKeyLabel = HkdfUtil.expandQuicKeyLabel( clientConnectionId );
        assertArrayEquals( new byte[]{
                (byte)0x00, (byte)0x10, (byte)0x0e, (byte)0x74, (byte)0x6c, (byte)0x73, (byte)0x31, (byte)0x33,
                (byte)0x20, (byte)0x71, (byte)0x75, (byte)0x69, (byte)0x63, (byte)0x20, (byte)0x6b, (byte)0x65,
                (byte)0x79, (byte)0x00
        }, quicKeyLabel );
    }

    @Test
    public void expandQuicIvLabel_givenAppendixADefinedClientConnectionId_matchesSpecExample() {
        byte[] quicIvLabel = HkdfUtil.expandQuicIvLabel( clientConnectionId );
        assertArrayEquals( new byte[]{
                (byte)0x00, (byte)0x0c, (byte)0x0d, (byte)0x74, (byte)0x6c, (byte)0x73, (byte)0x31, (byte)0x33,
                (byte)0x20, (byte)0x71, (byte)0x75, (byte)0x69, (byte)0x63, (byte)0x20, (byte)0x69, (byte)0x76,
                (byte)0x00
        }, quicIvLabel );
    }

    @Test
    public void expandQuicHpLabel_givenAppendixADefinedClientConnectionId_matchesSpecExample() {
        byte[] quicHpLabel = HkdfUtil.expandQuicHpLabel( clientConnectionId );
        assertArrayEquals( new byte[]{
                (byte)0x00, (byte)0x10, (byte)0x0d, (byte)0x74, (byte)0x6c, (byte)0x73, (byte)0x31, (byte)0x33,
                (byte)0x20, (byte)0x71, (byte)0x75, (byte)0x69, (byte)0x63, (byte)0x20, (byte)0x68, (byte)0x70,
                (byte)0x00
        }, quicHpLabel );
    }

    // </editor-fold>

    // <editor-fold desc="Test Expand Secrets">

    @Test
    public void expandInitialSecret_givenAppendixADefinedClientConnectionId_matchesSpecExample() {
        byte[] initialSecret = InitialPacketProtectionImpl.extractInitialSecret( clientConnectionId );
        assertArrayEquals( new byte[]{
                (byte)0x1e, (byte)0x7e, (byte)0x77, (byte)0x64, (byte)0x52, (byte)0x97, (byte)0x15, (byte)0xb1,
                (byte)0xe0, (byte)0xdd, (byte)0xc8, (byte)0xe9, (byte)0x75, (byte)0x3c, (byte)0x61, (byte)0x57,
                (byte)0x67, (byte)0x69, (byte)0x60, (byte)0x51, (byte)0x87, (byte)0x79, (byte)0x3e, (byte)0xd3,
                (byte)0x66, (byte)0xf8, (byte)0xbb, (byte)0xf8, (byte)0xc9, (byte)0xe9, (byte)0x86, (byte)0xeb
        }, initialSecret );
    }

    @Test
    public void expandClientInitialSecret_givenAppendixADefinedClientConnectionId_matchesSpecExample() {
        byte[] initialSecret = InitialPacketProtectionImpl.extractInitialSecret( clientConnectionId );
        byte[] clientInitialSecret =
                InitialPacketProtectionImpl.expandInitialClientSecret( initialSecret );
        assertArrayEquals( new byte[]{
                (byte)0x00, (byte)0x88, (byte)0x11, (byte)0x92, (byte)0x88, (byte)0xf1, (byte)0xd8, (byte)0x66,
                (byte)0x73, (byte)0x3c, (byte)0xee, (byte)0xed, (byte)0x15, (byte)0xff, (byte)0x9d, (byte)0x50,
                (byte)0x90, (byte)0x2c, (byte)0xf8, (byte)0x29, (byte)0x52, (byte)0xee, (byte)0xe2, (byte)0x7e,
                (byte)0x9d, (byte)0x4d, (byte)0x49, (byte)0x18, (byte)0xea, (byte)0x37, (byte)0x1d, (byte)0x87
        }, clientInitialSecret );
    }

    @Test
    public void expandServerInitialSecret_givenAppendixADefinedClientConnectionId_matchesSpecExample() {
        byte[] initialSecret = InitialPacketProtectionImpl.extractInitialSecret( clientConnectionId );
        byte[] serverInitialSecret =
                InitialPacketProtectionImpl.expandInitialServerSecret( initialSecret );
        assertArrayEquals( new byte[]{
                (byte)0x00, (byte)0x6f, (byte)0x88, (byte)0x13, (byte)0x59, (byte)0x24, (byte)0x4d, (byte)0xd9,
                (byte)0xad, (byte)0x1a, (byte)0xcf, (byte)0x85, (byte)0xf5, (byte)0x95, (byte)0xba, (byte)0xd6,
                (byte)0x7c, (byte)0x13, (byte)0xf9, (byte)0xf5, (byte)0x58, (byte)0x6f, (byte)0x5e, (byte)0x64,
                (byte)0xe1, (byte)0xac, (byte)0xae, (byte)0x1d, (byte)0x9e, (byte)0xa8, (byte)0xf6, (byte)0x16
        }, serverInitialSecret );
    }

    @Test
    public void expandHeaderProtectionForClient_givenAppendixADefinedClientConnectionId_matchesSpecExample() {
        byte[] initialSecret = InitialPacketProtectionImpl.extractInitialSecret( clientConnectionId );
        byte[] clientInitialSecret =
                InitialPacketProtectionImpl.expandInitialClientSecret( initialSecret );
        byte[] headerProtectionSecret =
                InitialPacketProtectionImpl.expandInitialHeaderProtection( clientInitialSecret );
        assertArrayEquals( new byte[]{
                (byte)0x9d, (byte)0xdd, (byte)0x12, (byte)0xc9, (byte)0x94, (byte)0xc0, (byte)0x69, (byte)0x8b,
                (byte)0x89, (byte)0x37, (byte)0x4a, (byte)0x9c, (byte)0x07, (byte)0x7a, (byte)0x30, (byte)0x77
        }, headerProtectionSecret );
    }

    @Test
    public void expandQuicKeyForClient_givenAppendixADefinedClientConnectionId_matchesSpecExample() {
        byte[] initialSecret = InitialPacketProtectionImpl.extractInitialSecret( clientConnectionId );
        byte[] clientInitialSecret = InitialPacketProtectionImpl.expandInitialClientSecret( initialSecret );
        byte[] quicKey = InitialPacketProtectionImpl.expandInitialQuicKey( clientInitialSecret );
        assertArrayEquals( new byte[]{
                (byte)0x17, (byte)0x52, (byte)0x57, (byte)0xa3, (byte)0x1e, (byte)0xb0, (byte)0x9d, (byte)0xea,
                (byte)0x93, (byte)0x66, (byte)0xd8, (byte)0xbb, (byte)0x79, (byte)0xad, (byte)0x80, (byte)0xba
        }, quicKey );
    }

    @Test
    public void expandQuicIvForClient_givenAppendixADefinedClientConnectionId_matchesSpecExample() {
        byte[] initialSecret = InitialPacketProtectionImpl.extractInitialSecret( clientConnectionId );
        byte[] clientInitialSecret = InitialPacketProtectionImpl.expandInitialClientSecret( initialSecret );
        byte[] quicIv = InitialPacketProtectionImpl.expandInitialQuicIv( clientInitialSecret );
        assertArrayEquals( new byte[]{
                (byte)0x6b, (byte)0x26, (byte)0x11, (byte)0x4b, (byte)0x9c, (byte)0xba, (byte)0x2b, (byte)0x63,
                (byte)0xa9, (byte)0xe8, (byte)0xdd, (byte)0x4f
        }, quicIv );
    }

    @Test
    public void expandHeaderProtectionForServer_givenAppendixADefinedClientConnectionId_matchesSpecExample() {
        byte[] initialSecret = InitialPacketProtectionImpl.extractInitialSecret( clientConnectionId );
        byte[] serverInitialSecret =
                InitialPacketProtectionImpl.expandInitialServerSecret( initialSecret );
        byte[] headerProtectionSecret =
                InitialPacketProtectionImpl.expandInitialHeaderProtection( serverInitialSecret );
        assertArrayEquals( new byte[]{
                (byte)0xc0, (byte)0xc4, (byte)0x99, (byte)0xa6, (byte)0x5a, (byte)0x60, (byte)0x02, (byte)0x4a,
                (byte)0x18, (byte)0xa2, (byte)0x50, (byte)0x97, (byte)0x4e, (byte)0xa0, (byte)0x1d, (byte)0xfa
        }, headerProtectionSecret );
    }

    @Test
    public void expandQuicKeyForServer_givenAppendixADefinedClientConnectionId_matchesSpecExample() {
        byte[] initialSecret = InitialPacketProtectionImpl.extractInitialSecret( clientConnectionId );
        byte[] serverInitialSecret = InitialPacketProtectionImpl.expandInitialServerSecret( initialSecret );
        byte[] quicKey = InitialPacketProtectionImpl.expandInitialQuicKey( serverInitialSecret );
        assertArrayEquals( new byte[]{
                (byte)0x14, (byte)0x9d, (byte)0x0b, (byte)0x16, (byte)0x62, (byte)0xab, (byte)0x87, (byte)0x1f,
                (byte)0xbe, (byte)0x63, (byte)0xc4, (byte)0x9b, (byte)0x5e, (byte)0x65, (byte)0x5a, (byte)0x5d
        }, quicKey );
    }

    @Test
    public void expandQuicIvForServer_givenAppendixADefinedClientConnectionId_matchesSpecExample() {
        byte[] initialSecret = InitialPacketProtectionImpl.extractInitialSecret( clientConnectionId );
        byte[] serverInitialSecret = InitialPacketProtectionImpl.expandInitialServerSecret( initialSecret );
        byte[] quicIv = InitialPacketProtectionImpl.expandInitialQuicIv( serverInitialSecret );
        assertArrayEquals( new byte[]{
                (byte)0xba, (byte)0xb2, (byte)0xb1, (byte)0x2a, (byte)0x4c, (byte)0x76, (byte)0x01, (byte)0x6a,
                (byte)0xce, (byte)0x47, (byte)0x85, (byte)0x6d
        }, quicIv );
    }

    // </editor-fold>

    @Test
    public void deriveHeaderProtectionMask_givenAppendixADefinedClientConnectionId_matchesSpecExample()
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        InitialPacketProtectionImpl ippi = new InitialPacketProtectionImpl( EndpointRole.SERVER );
        ippi.initialize( clientConnectionId );
        byte[] sample = new byte[]{
                (byte)0xfb, (byte)0x66, (byte)0xbc, (byte)0x6a, (byte)0x93, (byte)0x03, (byte)0x2b, (byte)0x50,
                (byte)0xdd, (byte)0x89, (byte)0x73, (byte)0x97, (byte)0x2d, (byte)0x14, (byte)0x94, (byte)0x21
        };
        byte[] mask = ippi.deriveHeaderProtectionMask( sample, 0, sample.length );
        assertArrayEquals( new byte[]{
                (byte)0x1e, (byte)0x9c, (byte)0xdb, (byte)0x99, (byte)0x09
        }, Arrays.copyOfRange( mask, 0, 5 ) );
    }

    @Test
    public void deriveAeadNonce_givenAppendixADefinedClientConnectionId_correct()
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        // The examples of Appendix A do not state the nonce to by created, but by testing the code manually
        // the nonce was found to be the value tested for here
        InitialPacketProtectionImpl ippi = new InitialPacketProtectionImpl( EndpointRole.SERVER );
        ippi.initialize( clientConnectionId );
        byte[] nonce = ippi.deriveAeadNonce( 2 /* packet number from the appendix a example */ );
        assertArrayEquals( new byte[]{(byte)0x6b, (byte)0x26, (byte)0x11, (byte)0x4b, (byte)0x9c, (byte)0xba,
                (byte)0x2b, (byte)0x63, (byte)0xa9, (byte)0xe8, (byte)0xdd, (byte)0x4d}, nonce );
    }
}
