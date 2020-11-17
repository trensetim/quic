package com.timtrense.quic;

/**
 * Convenience helper for converting hex-strings in test cases to byte-arrays
 *
 * @author Tim Trense, Nice people from StackOverflow
 * @see <a href="https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java">Stack Overflow Accepted Answer</a>
 */
public class HexByteStringConvertHelper {

    public static byte[] hexStringToByteArray( String s ) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for ( int i = 0; i < len; i += 2 ) {
            data[i / 2] = (byte)( ( Character.digit( s.charAt( i ), 16 ) << 4 )
                    + Character.digit( s.charAt( i + 1 ), 16 ) );
        }
        return data;
    }
}
