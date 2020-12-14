package com.timtrense.quic.tls;

import java.nio.ByteBuffer;

import org.junit.BeforeClass;
import org.junit.Test;

import com.timtrense.quic.HexByteStringConvertHelper;
import com.timtrense.quic.impl.exception.QuicParsingException;
import com.timtrense.quic.tls.impl.ExtensionParserImpl;
import com.timtrense.quic.tls.impl.MessageParserImpl;

import static org.junit.Assert.assertNotNull;

public class MessageParserImplTest {

    private static byte[] cryptoPayloadAppendixA;

    @BeforeClass
    public static void prepareProtectedIntialPacket() {

        String hexdumpFromAppendixA =
                // skip 060040f1 as these are the encoded preceding crypto frame fields
                " 010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868" +
                        " 04fe3a47f06a2b69484c00 00 04 1301 1302 01 00 00 c0 00 0000 10 000e00000b6578" +
                        " 616d706c652e636f6d ff01 00 01 00 000a 0008 0006 001d 0017 0018" +
                        " 0010 0007 0005 04 616c706e" + // ALPN
                        " 0005 0005 01 0000 0000" + // Certificate Status Request
                        " 0033 0026 0024 001d 0020" + // Key Share
                        " 9370b2c9caa47fba" +
                        " baf4559fedba753d" +
                        " e171fa71f50f1ce1" +
                        " 5d43e994ec74d748" +
                        " 002b 0003 02 0304 " + // Supported Versions
                        " 000d 0010 000e 0403 0503 0603 0203 0804 0805 0806 " + // Signature Algorithms
                        " 002d 0002 01 01 " + // Key Exchange Modes
                        " 001c 0002 4001 " + // Record Size Limit
                        " ffa5 0032" + // QUIC Transport Parameters
                        " 04 08 ffffffffffffffff" + // .. INITIAL_MAX_DATA
                        " 05 04 8000ffff" + // .. INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
                        " 07 04 8000ffff" + // .. INITIAL_MAX_STREAM_DATA_UNI
                        " 08 01 10" + // .. INITIAL_MAX_STREAMS_BIDI
                        " 01 04 80007530" + // .. MAX_IDLE_TIMEOUT
                        " 09 01 10 " + // .. INITIAL_MAX_STREAMS_UNI
                        " 0f 08 8394c8f03e515708" + // .. INITIAL_SOURCE_CONNECTION_ID
                        " 06 04 8000ffff"; // .. INITIAL_MAX_STREAM_DATA_BIDI_REMOTE

        hexdumpFromAppendixA = hexdumpFromAppendixA.replaceAll( " ", "" );
        cryptoPayloadAppendixA = HexByteStringConvertHelper.hexStringToByteArray( hexdumpFromAppendixA );
    }

    @Test
    public void parseMessage_givenAppendixAContent_givesClientHello() throws QuicParsingException {
        MessageParserImpl messageParser = new MessageParserImpl();
        messageParser.setExtensionParser( new ExtensionParserImpl() );
        ByteBuffer data = ByteBuffer.wrap( cryptoPayloadAppendixA );

        Handshake handshake = messageParser.parseMessage( data, cryptoPayloadAppendixA.length );

        assertNotNull( handshake );
    }

}
