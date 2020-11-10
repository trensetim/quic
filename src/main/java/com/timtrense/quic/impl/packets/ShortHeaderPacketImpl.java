package com.timtrense.quic.impl.packets;

import java.util.LinkedList;
import java.util.List;
import lombok.Data;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import com.timtrense.quic.ConnectionId;
import com.timtrense.quic.Frame;
import com.timtrense.quic.PacketNumber;
import com.timtrense.quic.ShortHeaderPacket;

/**
 * For all details on this class, see {@link ShortHeaderPacket}
 *
 * @author Tim Trense
 */
@Data
@RequiredArgsConstructor
public class ShortHeaderPacketImpl implements ShortHeaderPacket {

    private byte flags;
    private ConnectionId destinationConnectionId;
    private PacketNumber packetNumber;
    private final @NonNull List<Frame> payload = new LinkedList<>();

    @Override
    public boolean isPacketValid() {
        return ( ( flags & 0b10000000 ) == 0b00000000 ) // header form = short (0)
                && ( ( flags & 0b01000000 ) == 0b01000000 ) // fixed bit
                // spin bit may have arbitrary value
                // key phase bit may have arbitrary value
                && ( ( flags & 0b00000011 ) != 0b00000000 ) // packet number length may not be zero
                && packetNumber != null
                && destinationConnectionId != null;
    }

}
