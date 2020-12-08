package com.timtrense.quic.tls.impl;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import lombok.NonNull;

import com.timtrense.quic.impl.base.VariableLengthIntegerEncoder;
import com.timtrense.quic.impl.exception.MalformedTlsException;
import com.timtrense.quic.impl.exception.QuicParsingException;
import com.timtrense.quic.tls.CertificateStatusType;
import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionCarryingHandshake;
import com.timtrense.quic.tls.ExtensionType;
import com.timtrense.quic.tls.HostName;
import com.timtrense.quic.tls.KeyShareEntry;
import com.timtrense.quic.tls.NameType;
import com.timtrense.quic.tls.NamedGroup;
import com.timtrense.quic.tls.OcspExtensions;
import com.timtrense.quic.tls.OcspResponderId;
import com.timtrense.quic.tls.ProtocolName;
import com.timtrense.quic.tls.ServerName;
import com.timtrense.quic.tls.extensions.ApplicationLayerProtocolNegotiationExtension;
import com.timtrense.quic.tls.extensions.KeyShareClientHelloExtension;
import com.timtrense.quic.tls.extensions.KeyShareExtensionBase;
import com.timtrense.quic.tls.extensions.KeyShareHelloRetryRequestExtension;
import com.timtrense.quic.tls.extensions.KeyShareServerHelloExtension;
import com.timtrense.quic.tls.extensions.RenegotiationInfoExtension;
import com.timtrense.quic.tls.extensions.ServerNameIndicationExtension;
import com.timtrense.quic.tls.extensions.StatusRequestExtensionBase;
import com.timtrense.quic.tls.extensions.StatusRequestOcspExtension;
import com.timtrense.quic.tls.extensions.SupportedGroupsExtension;
import com.timtrense.quic.tls.handshake.ClientHello;
import com.timtrense.quic.tls.handshake.HelloRetryRequest;
import com.timtrense.quic.tls.handshake.ServerHello;

/**
 * Default implementation for {@link MessageParser}
 *
 * @author Tim Trense
 */
public class ExtensionParserImpl implements ExtensionParser {

    @Override
    public Extension parseExtension(
            @NonNull ExtensionCarryingHandshake handshake,
            @NonNull ByteBuffer data,
            int maxLength )
            throws QuicParsingException {

        // 1. Extension.extensionType
        int extensionTypeRaw = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
        ExtensionType extensionType = ExtensionType.findByValue( extensionTypeRaw );
        if ( extensionType == null ) {
            throw new MalformedTlsException( "Invalid TLS extension type: " + extensionTypeRaw );
        }

        int extensionDataLength = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );

        // 3. Extension.typeSpecificContent
        switch ( extensionType ) {
            case SERVER_NAME:
                return parseServerName( data, extensionDataLength );
            case SUPPORTED_GROUPS:
                return parseSupportedGroups( data, extensionDataLength );
            case RENEGOTIATION_INFO:
                return parseRenegotiationInfo( data, extensionDataLength );
            case APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
                return parseApplicationLayerProtocolNegotiation( data, extensionDataLength );
            case STATUS_REQUEST:
                return parseStatusRequest( data, extensionDataLength );
            case KEY_SHARE:
                return parseKeyShare( handshake, data, extensionDataLength );
            // TODO: other cases
            default:
                throw new MalformedTlsException( "Unimplemented TLS handshake message type: " + extensionType.name() );
        }
    }

    private ServerNameIndicationExtension parseServerName( ByteBuffer data, int maxLength )
            throws MalformedTlsException {
        // https://tools.ietf.org/html/rfc6066#section-3

        int serverNameListLength = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
        List<ServerName> serverNameList = new ArrayList<>( serverNameListLength / 10 + 1 );
        while ( serverNameListLength > 0 ) {
            int nameTypeRaw = data.get() & 0xff;
            NameType nameType = NameType.findByValue( nameTypeRaw );
            if ( nameType == null ) {
                throw new MalformedTlsException( "Invalid NameType.value: " + nameTypeRaw );
            }
            if ( nameType != NameType.HOST_NAME ) {
                throw new MalformedTlsException( "Unimplemented NameType.value: " + nameType );
            }
            int hostNameLength = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
            byte[] hostNameRaw = new byte[hostNameLength];
            data.get( hostNameRaw );
            HostName hostName = new HostName( hostNameRaw );
            serverNameList.add( hostName );
            serverNameListLength -= ( 1/*nameTypeRaw*/ + 2 /*hostNameLength*/ + hostNameLength );
        }

        ServerNameIndicationExtension extension = new ServerNameIndicationExtension();
        ServerName[] serverNames = new ServerName[serverNameList.size()];
        extension.setServerNameList( serverNameList.toArray( serverNames ) );
        return extension;
    }

    private SupportedGroupsExtension parseSupportedGroups( ByteBuffer data, int extensionDataLength )
            throws MalformedTlsException {
        int namedGroupListLength = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
        // all named group values are 2 bytes wide, so length of the list is half the length in bytes
        namedGroupListLength /= 2;
        NamedGroup[] namedGroupList = new NamedGroup[namedGroupListLength];

        for ( int i = 0; i < namedGroupListLength; i++ ) {
            NamedGroup group = parseNamedGroup( data );
            namedGroupList[i] = group;
        }

        SupportedGroupsExtension extension = new SupportedGroupsExtension();
        extension.setNamedGroupList( namedGroupList );
        return extension;
    }

    private RenegotiationInfoExtension parseRenegotiationInfo( ByteBuffer data, int maxLength ) {
        // https://tools.ietf.org/html/rfc5746#section-3.2

        int length = data.get() & 0xff;
        byte[] renegotiationInfoRaw = new byte[length];
        data.get( renegotiationInfoRaw );

        RenegotiationInfoExtension extension = new RenegotiationInfoExtension();
        extension.setRenegotiatedConnection( renegotiationInfoRaw );

        return extension;
    }

    private ApplicationLayerProtocolNegotiationExtension parseApplicationLayerProtocolNegotiation(
            ByteBuffer data, int maxLength ) {
        int protocolNamesListLength = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
        // randomly approximating list length
        List<ProtocolName> protocolNamesList = new ArrayList<>( protocolNamesListLength / 10 + 1 );
        while ( protocolNamesListLength > 0 ) {
            int protocolNameLength = data.get() & 0xff;
            byte[] protocolNameRaw = new byte[protocolNameLength];
            data.get( protocolNameRaw );
            ProtocolName protocolName = new ProtocolName( protocolNameRaw );
            protocolNamesList.add( protocolName );
            protocolNamesListLength -= protocolNameLength + 1 /* protocolNameLength */;
        }

        ProtocolName[] protocolNames = new ProtocolName[protocolNamesList.size()];
        protocolNamesList.toArray( protocolNames );
        ApplicationLayerProtocolNegotiationExtension extension = new ApplicationLayerProtocolNegotiationExtension();
        extension.setProtocolNameList( protocolNames );
        return extension;
    }

    private StatusRequestExtensionBase parseStatusRequest(
            ByteBuffer data, int maxLength ) throws MalformedTlsException {
        int certificateStatusTypeRaw = data.get() & 0xff;
        CertificateStatusType certificateStatusType = CertificateStatusType.findByValue( certificateStatusTypeRaw );
        if ( certificateStatusType == null ) {
            throw new MalformedTlsException( "Invalid CertificateStatusType.value: " + certificateStatusTypeRaw );
        }
        if ( certificateStatusType != CertificateStatusType.OCSP ) {
            throw new MalformedTlsException( "Unimplemented CertificateStatusType." + certificateStatusType.name() );
        }
        int responderIdListLength = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
        // randomly approximate list length
        List<OcspResponderId> responderIdList = new ArrayList<>( responderIdListLength / 10 + 1 );
        while ( responderIdListLength > 0 ) {
            int responderIdLength = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
            byte[] responderIdRaw = new byte[responderIdLength];
            data.get( responderIdRaw );
            OcspResponderId responderId = new OcspResponderId( responderIdRaw );
            responderIdList.add( responderId );
            responderIdListLength -= responderIdListLength + 2 /* responderIdListLength */;
        }
        OcspResponderId[] responderIds = new OcspResponderId[responderIdList.size()];
        responderIdList.toArray( responderIds );

        int requestExtensionsLength = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
        byte[] requestExtensionsRaw = new byte[requestExtensionsLength];
        data.get( requestExtensionsRaw );
        OcspExtensions requestExtensions = new OcspExtensions( requestExtensionsRaw );

        StatusRequestOcspExtension extension = new StatusRequestOcspExtension();
        extension.setResponderIdList( responderIds );
        extension.setRequestExtensions( requestExtensions );
        return extension;
    }

    private KeyShareExtensionBase parseKeyShare(
            ExtensionCarryingHandshake handshake, ByteBuffer data, int maxLength ) throws MalformedTlsException {
        KeyShareExtensionBase extension;
        if ( handshake instanceof ClientHello ) {
            int clientSharesLength = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
            // randomly approximate length of list
            List<KeyShareEntry> clientSharesList = new ArrayList<>( clientSharesLength / 10 + 1 );
            while ( clientSharesLength > 0 ) {
                KeyShareEntry entry = parseKeyShareEntry( data, clientSharesLength );
                clientSharesList.add( entry );
                clientSharesLength -= entry.getKeyExchange().length + 2 + 2 /* named group + keyExchange.length*/;
            }
            KeyShareEntry[] clientShares = new KeyShareEntry[clientSharesList.size()];
            clientSharesList.toArray( clientShares );

            extension = new KeyShareClientHelloExtension();
            ( (KeyShareClientHelloExtension)extension ).setClientShares( clientShares );
        }
        else if ( handshake instanceof HelloRetryRequest ) {
            NamedGroup selectedGroup = parseNamedGroup( data );
            extension = new KeyShareHelloRetryRequestExtension();
            ( (KeyShareHelloRetryRequestExtension)extension ).setSelectedGroup( selectedGroup );
        }
        else if ( handshake instanceof ServerHello ) {
            KeyShareEntry serverShare = parseKeyShareEntry( data, maxLength );
            extension = new KeyShareServerHelloExtension();
            ( (KeyShareServerHelloExtension)extension ).setServerShare( serverShare );
        }
        else {
            throw new MalformedTlsException( "illegal KEY_SHARE extension in message of type "
                    + handshake.getClass().getSimpleName() );
        }

        return extension;
    }

    private KeyShareEntry parseKeyShareEntry( ByteBuffer data, int maxLength ) throws MalformedTlsException {
        NamedGroup namedGroup = parseNamedGroup( data );
        int keyExchangeLength = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
        byte[] keyExchange = new byte[keyExchangeLength];
        data.get( keyExchange );

        KeyShareEntry entry = new KeyShareEntry();
        entry.setGroup( namedGroup );
        entry.setKeyExchange( keyExchange );
        return entry;
    }

    private NamedGroup parseNamedGroup( ByteBuffer data ) throws MalformedTlsException {
        int namedGroupRaw = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
        NamedGroup namedGroup = NamedGroup.findByValue( namedGroupRaw );
        if ( namedGroup == null ) {
            throw new MalformedTlsException( "Invalid NamedGroup.value: " + namedGroupRaw );
        }
        return namedGroup;
    }
}
