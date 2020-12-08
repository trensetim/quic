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
                        " 616d706c652e636f6d ff01 00 01 00 000a 0008 0006 001d 0017 0018 001000070005" +
                        " 04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba" +
                        " baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400" +
                        " 0d0010000e0403050306030203080408 050806002d00020101001c00024001ff" +
                        " a500320408ffffffffffffffff050480 00ffff07048000ffff08011001048000" +
                        " 75300901100f088394c8f03e51570806 048000ffff";

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
