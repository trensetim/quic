package com.timtrense.quic.impl;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import com.timtrense.quic.*;
import com.timtrense.quic.impl.base.*;
import lombok.Data;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import com.timtrense.quic.impl.exception.MalformedDatagramException;
import com.timtrense.quic.impl.exception.MalformedPacketException;
import com.timtrense.quic.impl.exception.OutOfOrderProtectedPacketException;
import com.timtrense.quic.impl.exception.QuicParsingException;
import com.timtrense.quic.impl.exception.UnsupportedProtocolVersionException;
import com.timtrense.quic.impl.packets.HandshakePacketImpl;
import com.timtrense.quic.impl.packets.InitialPacketImpl;
import com.timtrense.quic.impl.packets.RetryPacketImpl;
import com.timtrense.quic.impl.packets.VersionNegotiationPacketImpl;
import com.timtrense.quic.impl.packets.ZeroRttPacketImpl;

import javax.crypto.NoSuchPaddingException;

@Data
@RequiredArgsConstructor
public class PacketParserImpl implements PacketParser {

    private @NonNull FrameParser frameParser;
    /**
     * external information known by this endpoint and required for parsing
     */
    private @NonNull ParsingContext context;

    /**
     * Creates a new parser with a frame parser of type {@link FrameParserImpl}
     */
    public PacketParserImpl(@NonNull ParsingContext context) {
        this(new FrameParserImpl(context), context);
    }

    @Override
    public Packet parsePacket(
            ReceivedDatagram receivedDatagram,
            ByteBuffer data,
            int packetIndex
    ) throws QuicParsingException {
        if (data.remaining() < 2) {
            throw new MalformedDatagramException(receivedDatagram, data);
        }
        byte flags = data.get();
        if ((flags & 0b01000000) != 0b01000000) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.3
            // "Fixed Bit:  The next bit (0x40) of byte 0 is set to 1.  Packets
            //      containing a zero value for this bit are not valid packets in this
            //      version and MUST be discarded."
            throw new MalformedPacketException(receivedDatagram, data, data.position() - 1);
        }

        if ((flags & 0b10000000) == 0b10000000) {
            return parseLongHeaderPacket(receivedDatagram, flags, data, packetIndex);
        } else {
            return parseShortHeaderPacket(flags, data);
        }
    }

    public LongHeaderPacket parseLongHeaderPacket(ReceivedDatagram datagram, byte flags,
                                                  ByteBuffer remainingData, int packetIndex)
            throws QuicParsingException {
        int version = remainingData.getInt();
        if (version == ProtocolVersion.RESERVED_FOR_VERSION_NEGOTIATION.getValue()) {
            return new VersionNegotiationPacketImpl();
        }
        ProtocolVersion protocolVersion = ProtocolVersion.findByValue(version);
        if ( protocolVersion == null ||
                ( ( protocolVersion.isIetfDraft() && protocolVersion.getIetfDraftVersion() < 29 )
                && protocolVersion != ProtocolVersion.ONE ) ) {
            throw new UnsupportedProtocolVersionException(version);
        }
        switch ((flags & 0b00110000)) {
            case 0b00000000:
                return parseInitialPacket(datagram, flags, protocolVersion, remainingData, packetIndex);
            case 0b00010000:
                return parse0RttPacket(datagram, flags, protocolVersion, remainingData, packetIndex);
            case 0b00100000:
                return parseHandshakePacket(datagram, flags, protocolVersion, remainingData, packetIndex);
            case 0b00110000:
                return parseRetryPacket(datagram, flags, protocolVersion, remainingData, packetIndex);
            default:
                // cannot happen due to arithmetics.
                // if it does happen though, something is broken in
                // the world of math and the universe will collapse
                return null;
        }
    }

    public RetryPacketImpl parseRetryPacket(ReceivedDatagram datagram, byte flags,
                                            ProtocolVersion protocolVersion, ByteBuffer remainingData, int packetIndex) {
        return null; // TODO implement
    }

    public HandshakePacketImpl parseHandshakePacket(ReceivedDatagram datagram, byte flags,
                                                    ProtocolVersion protocolVersion, ByteBuffer remainingData, int packetIndex) {
        return null; // TODO implement
    }

    public ZeroRttPacketImpl parse0RttPacket(ReceivedDatagram datagram, byte flags,
                                             ProtocolVersion protocolVersion, ByteBuffer remainingData, int packetIndex) {
        return null; // TODO implement
    }

    public ShortHeaderPacket parseShortHeaderPacket(byte flags, ByteBuffer remainingData) {
        return null; // TODO implement
    }

    public InitialPacketImpl parseInitialPacket(ReceivedDatagram datagram, byte flags,
                                                ProtocolVersion protocolVersion, ByteBuffer remainingData, int packetIndex)
            throws QuicParsingException {
        InitialPacketImpl initialPacket = new InitialPacketImpl();
        initialPacket.setVersion(protocolVersion);

        // DESTINATION CONNECTION ID
        int dstConnIdLength = remainingData.get() & 0xFF;
        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2
        // "In QUIC version 1, this value MUST NOT exceed 20. Endpoints that receive a version 1 long header with a
        // value larger than 20 MUST drop the packet."
        if (dstConnIdLength > 20) {
            throw new MalformedPacketException("Out-Of-Bounds (20) Destination Connection ID: " + dstConnIdLength,
                    datagram, remainingData, packetIndex);
        }
        byte[] dstConnId = new byte[dstConnIdLength];
        remainingData.get(dstConnId);
        ConnectionId dstConnIdImpl = new ConnectionIdImpl(dstConnId, VariableLengthInteger.ZERO);
        initialPacket.setDestinationConnectionId(dstConnIdImpl);
        initialPacket.setDestinationConnectionIdLength(dstConnIdLength);

        // SOURCE CONNECTION ID
        int srcConnIdLength = remainingData.get() & 0xFF;
        if (srcConnIdLength > 20) {
            throw new MalformedPacketException("Out-Of-Bounds (20) Source Connection ID: " + srcConnIdLength,
                    datagram, remainingData, packetIndex);
        }
        byte[] srcConnId = new byte[srcConnIdLength];
        remainingData.get(srcConnId);
        // The initial connection ID issued by an endpoint
        //   is sent in the Source Connection ID field of the long packet header
        //   (Section 17.2) during the handshake.  The sequence number of the
        //   initial connection ID is 0.  If the preferred_address transport
        //   parameter is sent, the sequence number of the supplied connection ID
        //   is 1.
        //      The sequence number will be corrected on parsing a crypto frame with the preferred_address being set
        ConnectionId srcConnIdImpl = new ConnectionIdImpl(srcConnId, VariableLengthInteger.ZERO);
        initialPacket.setSourceConnectionId(srcConnIdImpl);
        initialPacket.setSourceConnectionIdLength(srcConnIdLength);

        // TOKEN LENGTH
        VariableLengthInteger tokenLength = VariableLengthInteger.decode(remainingData);
        if (tokenLength == null) {
            throw new MalformedPacketException("Token Length is no valid VariableLengthInteger",
                    datagram, remainingData, packetIndex);
        }
        initialPacket.setTokenLength(tokenLength);

        // TOKEN
        byte[] token = new byte[tokenLength.intValue()];
        remainingData.get(token);

        // LENGTH
        VariableLengthInteger length = VariableLengthInteger.decode(remainingData);
        if (length == null) {
            throw new MalformedPacketException("Length is no valid VariableLengthInteger",
                    datagram, remainingData, packetIndex);
        }

        // PACKET NUMBER and DECRYPTED FLAGS
        // "This algorithm samples 16 bytes from the packet ciphertext." QUIC Spec-TLS/Section 5.4.3
        byte[] sample = new byte[16];
        int positionBeforeSampling = remainingData.position();
        // "The same number of bytes are always sampled, but an allowance needs
        //   to be made for the endpoint removing protection, which will not know
        //   the length of the Packet Number field.  In sampling the packet
        //   ciphertext, the Packet Number field is assumed to be 4 bytes long
        //   (its maximum possible encoded length)." QUIC Spec-TLS/Section 5.4.2
        remainingData.position(positionBeforeSampling + 4);
        remainingData.get(sample);
        remainingData.position(positionBeforeSampling);

        InitialPacketProtectionImpl packetProtection = new InitialPacketProtectionImpl(context.getRole());
        try {
            packetProtection.initialize(dstConnIdImpl);
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException e) {
            throw new OutOfOrderProtectedPacketException(datagram, remainingData, packetIndex);
        }
        byte[] headerProtectionMask = packetProtection.deriveHeaderProtectionMask(sample);

        // "The least significant
        //   bits of the first byte of the packet [that is, the flags] are masked by the least
        //   significant bits of the first mask byte..." QUIC Spec-TLS/Section 5.4.1
        byte decryptedFlags = (byte) (flags ^ headerProtectionMask[0] & 0b00001111); // long header: 4 bits masked
        initialPacket.setFlags(decryptedFlags);
        int unprotectedPacketNumberLength = initialPacket.getPacketNumberLength(); // call may be inlined?
        byte[] protectedPacketNumber = new byte[unprotectedPacketNumberLength];
        remainingData.get(protectedPacketNumber);
        // "[...] and the packet number is
        //   masked with the remaining bytes.  Any unused bytes of mask that might
        //   result from a shorter packet number encoding are unused." QUIC Spec-TLS/Section 5.4.1
        for (int i = 0; i < unprotectedPacketNumberLength; i++) {
            protectedPacketNumber[i] = (byte) (protectedPacketNumber[i] ^ headerProtectionMask[1 + i]);
        }
        long packetNumber = VariableLengthIntegerEncoder
                .decodeFixedLengthInteger(protectedPacketNumber, 0, unprotectedPacketNumberLength);
        packetNumber = PacketNumberEncoder.decodePacketNumber(
                packetNumber,
                0L,
                unprotectedPacketNumberLength << 3 /* effectively multiplying by 8 */
        );
        initialPacket.setPacketNumber(new PacketNumberImpl(packetNumber));

        List<Frame> frames = frameParser.parseFrames(initialPacket, remainingData, length.intValue());
        initialPacket.setPayload(frames);
        return initialPacket;
    }
}
