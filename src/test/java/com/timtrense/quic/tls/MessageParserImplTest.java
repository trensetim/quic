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
                        " 616d706c652e636f6d ff01 000100000a 00080006001d00170018001000070005" +
                        " 04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba" +
                        " baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400" +
                        " 0d0010000e0403050306030203080408 050806002d00020101001c00024001ff" +
                        " a500320408ffffffffffffffff050480 00ffff07048000ffff08011001048000" +
                        " 75300901100f088394c8f03e51570806 048000ffff";


//        String hexdumpFromAppendixA =
//                // skip 060040c4 as these are the encoded preceding crypto frame fields
//                " 010000c003036660261ff947 cea49cce6cfad687f457cf1b14531ba1" +
//                        "4131a0e8f309a1d0b9c4000006130113 031302010000910000000b0009000006" +
//                        "736572766572ff01000100000a001400 12001d00170018001901000101010201" +
//                        "03010400230000003300260024001d00 204cfdfcd178b784bf328cae793b136f" +
//                        "2aedce005ff183d7bb14952072366470 37002b0003020304000d0020001e0403" +
//                        "05030603020308040805080604010501 060102010402050206020202002d0002" +
//                        "0101001c00024001";
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
