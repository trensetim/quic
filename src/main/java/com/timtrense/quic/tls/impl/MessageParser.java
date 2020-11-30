package com.timtrense.quic.tls.impl;

import java.nio.ByteBuffer;
import lombok.NonNull;

import com.timtrense.quic.impl.exception.QuicParsingException;
import com.timtrense.quic.tls.Handshake;

/**
 * Interface to parsing TLS messages
 *
 * @author Tim Trense
 */
public interface MessageParser {

    /**
     * Parses one TLS 1.3 message from the given data on the wire.
     *
     * @param data      the raw data from the wire, positioned at the start of this message
     * @param maxLength the remaining length of the buffer, that this next message could take at most
     * @return a parsed, valid message
     * @throws QuicParsingException if any parsing error occurs
     */
    Handshake parseMessage(
            @NonNull ByteBuffer data,
            int maxLength )
            throws QuicParsingException;

    void setExtensionParser( @NonNull ExtensionParser extensionParser );

    ExtensionParser getExtensionParser();
}
