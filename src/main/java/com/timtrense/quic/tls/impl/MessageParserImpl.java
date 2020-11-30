package com.timtrense.quic.tls.impl;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import lombok.Data;
import lombok.NonNull;

import com.timtrense.quic.impl.base.VariableLengthIntegerEncoder;
import com.timtrense.quic.impl.exception.MalformedTlsException;
import com.timtrense.quic.impl.exception.QuicParsingException;
import com.timtrense.quic.tls.CipherSuite;
import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionCarryingHandshake;
import com.timtrense.quic.tls.Handshake;
import com.timtrense.quic.tls.HandshakeType;
import com.timtrense.quic.tls.handshake.ClientHello;
import com.timtrense.quic.tls.handshake.HelloRetryRequest;
import com.timtrense.quic.tls.handshake.ServerHello;

/**
 * Default implementation for {@link MessageParser}
 *
 * @author Tim Trense
 */
@Data
public class MessageParserImpl implements MessageParser {

    private ExtensionParser extensionParser;

    @Override
    public Handshake parseMessage(
            @NonNull ByteBuffer data,
            int maxLength )
            throws QuicParsingException {

        // 1. Handshake.messageType
        byte messageTypeRaw = data.get();
        HandshakeType messageType = HandshakeType.findByValue( messageTypeRaw );
        if ( messageType == null ) {
            throw new MalformedTlsException( "Invalid TLS handshake message type: " + messageTypeRaw );
        }

        // 2. Handshake.length
        long messageLength =
                VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 3 );
        if ( messageLength < 0 ) {
            throw new MalformedTlsException( "Could not decode TLS handshake message " +
                    "length for message of type: " + messageTypeRaw );
        }

        // 3. Handshake.typeSpecificContent
        switch ( messageType ) {
            case SERVER_HELLO:
                return parseServerHelloOrRetry( data, messageLength );
            case CLIENT_HELLO:
                return parseClientHello( data, messageLength );
            // todo: other cases
            default:
                throw new MalformedTlsException( "Unimplemented TLS handshake message type: " + messageType.name() );
        }
    }

    private ServerHello parseServerHelloOrRetry( ByteBuffer data, long messageLength ) throws QuicParsingException {
        ServerHello message;

        // 1. check fixed legacy_version
        checkLegacyVersion( data );
        // 2. random
        byte[] random = new byte[32];
        data.get( random );

        if ( Arrays.equals( HelloRetryRequest.SPECIFIC_RANDOM, random ) ) {
            message = new HelloRetryRequest();
        }
        else {
            message = new ServerHello();
        }
        message.setLength( (int)messageLength );

        // 3. legacy_session_id_echo
        // max length is 255, thus for length of length: 1 Byte is sufficient
        int legacySessionIdEchoLength = data.get() & 0xFF;
        byte[] legacySessionIdEcho = new byte[legacySessionIdEchoLength];
        data.get( legacySessionIdEcho );
        message.setLegacySessionIdEcho( legacySessionIdEcho );

        // 4. cipher_suite
        short cipherSuiteRaw = data.getShort();
        CipherSuite cipherSuite = CipherSuite.findByValue( cipherSuiteRaw );
        if ( cipherSuite == null ) {
            throw new MalformedTlsException( "Unknown CipherSuite for value: " + cipherSuiteRaw );
        }
        message.setCipherSuite( cipherSuite );

        // 5. legacy_compression_method
        int legacyCompressionMethod = data.get(); // A single byte which MUST have the value 0.
        if ( legacyCompressionMethod != 0 ) {
            throw new MalformedTlsException( "Protocol violation because legacy_compression_method != 0, actually: "
                    + legacyCompressionMethod );
        }

        // 6. extensions
        parseExtensions( message, data, messageLength );

        return message;
    }

    private ClientHello parseClientHello( ByteBuffer data, long messageLength ) throws QuicParsingException {
        ClientHello message = new ClientHello();

        // 1. check fixed legacy_version
        checkLegacyVersion( data );

        // 2. random
        byte[] random = new byte[32];
        data.get( random );
        message.setRandom( random );

        // 3. legacy_session_id
        // max length is 255, thus for length of length: 1 Byte is sufficient
        int legacySessionIdLength = data.get() & 0xFF;
        byte[] legacySessionId = new byte[legacySessionIdLength];
        data.get( legacySessionId );
        message.setLegacySessionId( legacySessionId );

        // 4. cipher_suites
        int cipherSuitesLength = ( data.getShort() & 0xFFFF ) / 2 /*2 bytes per cipher suite*/;
        CipherSuite[] cipherSuites = new CipherSuite[cipherSuitesLength];
        for ( int i = 0; i < cipherSuitesLength; i++ ) {
            short cipherSuiteRaw = data.getShort();
            CipherSuite cipherSuite = CipherSuite.findByValue( cipherSuiteRaw );
            if ( cipherSuite == null ) {
                throw new MalformedTlsException( "Invalid CipherSuite.value: " + cipherSuiteRaw );
            }
            cipherSuites[i] = cipherSuite;
        }
        message.setCipherSuites( cipherSuites );

        // 5. legacy_compression_methods
        int legacyCompressionMethodsLength = data.get() & 0xFF;
        byte[] legacyCompressionMethods = new byte[legacyCompressionMethodsLength];
        data.get( legacyCompressionMethods );
        message.setLegacyCompressionMethods( legacyCompressionMethods );

        // 6. extensions
        parseExtensions( message, data, messageLength );

        return message;
    }

    private int parseExtensions(
            ExtensionCarryingHandshake handshake,
            ByteBuffer data,
            long maxLength
    ) throws QuicParsingException {
        // max length is 65535, thus for length of length: 2 Bytes is sufficient
        int extensionDataLength = data.getShort();
        List<Extension> extensionList = handshake.getExtensions();
        while ( extensionDataLength > 0 ) {
            int positionBefore = data.position();
            Extension extension = extensionParser.parseExtension( data, extensionDataLength );
            if ( extension == null ) {
                throw new MalformedTlsException( "Parsed null Extension" );
            }
            extensionList.add( extension );
            int consumedBytes = data.position() - positionBefore;
            extensionDataLength -= consumedBytes;
        }
        return extensionDataLength;
    }

    private void checkLegacyVersion( ByteBuffer data ) throws MalformedTlsException {
        byte serverLegacyVersion1 = data.get();
        byte serverLegacyVersion2 = data.get();
        if ( serverLegacyVersion1 != 0x03 || serverLegacyVersion2 != 0x03 ) {
            // ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
            throw new MalformedTlsException( "Invalid ServerHello.legacy_version: "
                    + ( ( serverLegacyVersion1 << 8 ) | serverLegacyVersion2 ) );
        }
    }


}
