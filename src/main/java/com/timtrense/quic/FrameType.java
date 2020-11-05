package com.timtrense.quic;

import lombok.Getter;

/**
 * a frame type can have some bits set to indicate the very layout of the frame.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19">QUIC Spec/Section 19</a>
 * @see FrameGeneralType
 */
public enum FrameType {

    // TODO: find better names for _1, _2, ...

    PADDING( 0x00, FrameGeneralType.PADDING ),
    PING( 0x01, FrameGeneralType.PING ),
    ACK( 0x02, FrameGeneralType.ACK ),
    ACK_WITH_ECN( 0x03, FrameGeneralType.ACK ),
    RESET_STREAM( 0x04, FrameGeneralType.RESET_STREAM ),
    STOP_SENDING( 0x05, FrameGeneralType.STOP_SENDING ),
    CRYPTO( 0x06, FrameGeneralType.CRYPTO ),
    NEW_TOKEN( 0x07, FrameGeneralType.NEW_TOKEN ),
    STREAM( 0x08, FrameGeneralType.STREAM ),
    STREAM_FIN( 0x09, FrameGeneralType.STREAM ),
    STREAM_LEN( 0x0a, FrameGeneralType.STREAM ),
    STREAM_LEN_FIN( 0x0b, FrameGeneralType.STREAM ),
    STREAM_OFF( 0x0c, FrameGeneralType.STREAM ),
    STREAM_OFF_FIN( 0x0d, FrameGeneralType.STREAM ),
    STREAM_OFF_LEN( 0x0e, FrameGeneralType.STREAM ),
    STREAM_OFF_LEN_FIN( 0x0f, FrameGeneralType.STREAM ),
    MAX_DATA( 0x10, FrameGeneralType.MAX_DATA ),
    MAX_STREAM_DATA( 0x11, FrameGeneralType.MAX_STREAM_DATA ),
    MAX_STREAMS_1( 0x12, FrameGeneralType.MAX_STREAMS ),
    MAX_STREAMS_2( 0x13, FrameGeneralType.MAX_STREAMS ),
    DATA_BLOCKED( 0x14, FrameGeneralType.DATA_BLOCKED ),
    STREAM_DATA_BLOCKED( 0x15, FrameGeneralType.STREAM_DATA_BLOCKED ),
    STREAMS_BLOCKED_1( 0x16, FrameGeneralType.STREAMS_BLOCKED ),
    STREAMS_BLOCKED_2( 0x17, FrameGeneralType.STREAMS_BLOCKED ),
    NEW_CONNECTION_ID( 0x18, FrameGeneralType.NEW_CONNECTION_ID ),
    RETIRE_CONNECTION_ID( 0x19, FrameGeneralType.RETIRE_CONNECTION_ID ),
    PATH_CHALLENGE( 0x1a, FrameGeneralType.PATH_CHALLENGE ),
    PATH_RESPONSE( 0x1b, FrameGeneralType.PATH_RESPONSE ),
    CONNECTION_CLOSE( 0x1c, FrameGeneralType.CONNECTION_CLOSE ),
    CONNECTION_CLOSE_ON_FRAME_TYPE( 0x1d, FrameGeneralType.CONNECTION_CLOSE ),
    HANDSHAKE_DONE( 0x1e, FrameGeneralType.HANDSHAKE_DONE );

    @Getter
    private final VariableLengthInteger value;
    @Getter
    private final FrameGeneralType generalType;

    FrameType( int value, FrameGeneralType generalType ) {
        this.value = new VariableLengthInteger( value );
        this.generalType = generalType;
    }

    /**
     * @return the value of {@link #getValue()} as a long
     */
    public long getLongValue() {
        return value.longValue();
    }

    public static FrameType findByValue( int value ) {
        for ( FrameType f : values() ) {
            if ( f.value.longValue() == value ) {
                return f;
            }
        }
        return null;
    }

    public static FrameType findByValue( VariableLengthInteger value ) {
        for ( FrameType f : values() ) {
            if ( f.value.equals( value ) ) {
                return f;
            }
        }
        return null;
    }
}
