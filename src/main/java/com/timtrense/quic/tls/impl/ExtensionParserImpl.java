package com.timtrense.quic.tls.impl;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import lombok.NonNull;

import at.favre.lib.bytes.BytesValidator;

import com.timtrense.quic.PreferredAddress;
import com.timtrense.quic.TransportParameter;
import com.timtrense.quic.TransportParameterType;
import com.timtrense.quic.VariableLengthInteger;
import com.timtrense.quic.impl.base.ByteArrayTransportParameterImpl;
import com.timtrense.quic.impl.base.ConnectionIdImpl;
import com.timtrense.quic.impl.base.FlagTransportParameterImpl;
import com.timtrense.quic.impl.base.IntegerTransportParameterImpl;
import com.timtrense.quic.impl.base.PreferredAddressImpl;
import com.timtrense.quic.impl.base.PreferredAddressTransportParameterImpl;
import com.timtrense.quic.impl.base.StatelessResetTokenImpl;
import com.timtrense.quic.impl.base.TransportParameterCollectionImpl;
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
import com.timtrense.quic.tls.ProtocolVersion;
import com.timtrense.quic.tls.PskKeyExchangeMode;
import com.timtrense.quic.tls.ServerName;
import com.timtrense.quic.tls.SignatureScheme;
import com.timtrense.quic.tls.extensions.ApplicationLayerProtocolNegotiationExtension;
import com.timtrense.quic.tls.extensions.ClientSupportedVersionsExtension;
import com.timtrense.quic.tls.extensions.KeyShareClientHelloExtension;
import com.timtrense.quic.tls.extensions.KeyShareExtensionBase;
import com.timtrense.quic.tls.extensions.KeyShareHelloRetryRequestExtension;
import com.timtrense.quic.tls.extensions.KeyShareServerHelloExtension;
import com.timtrense.quic.tls.extensions.PskKeyExchangeModeExtension;
import com.timtrense.quic.tls.extensions.QuicTransportParametersExtension;
import com.timtrense.quic.tls.extensions.RecordSizeLimitExtension;
import com.timtrense.quic.tls.extensions.RenegotiationInfoExtension;
import com.timtrense.quic.tls.extensions.ServerNameIndicationExtension;
import com.timtrense.quic.tls.extensions.ServerSupportedVersionsExtension;
import com.timtrense.quic.tls.extensions.SignatureAlgorithmsExtension;
import com.timtrense.quic.tls.extensions.StatusRequestExtensionBase;
import com.timtrense.quic.tls.extensions.StatusRequestOcspExtension;
import com.timtrense.quic.tls.extensions.SupportedGroupsExtension;
import com.timtrense.quic.tls.extensions.SupportedVersionsExtensionBase;
import com.timtrense.quic.tls.handshake.ClientHello;
import com.timtrense.quic.tls.handshake.HelloRetryRequest;
import com.timtrense.quic.tls.handshake.ServerHello;

/**
 * Default implementation for {@link MessageParser}
 *
 * @author Tim Trense
 */
public class ExtensionParserImpl implements ExtensionParser {

    /**
     * Byte-Array checking function to fire true if the array checked is not all zeros.
     * This is the
     */
    private static final BytesValidator NOT_ONLY_ZEROS = byteArrayToValidate -> {
        for ( byte b : byteArrayToValidate ) {
            if ( b != 0 ) {
                return true;
            }
        }
        return false;
    };

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
            case SUPPORTED_VERSIONS:
                return parseSupportedVersions( handshake, data, extensionDataLength );
            case SIGNATURE_ALGORITHMS:
                return parseSignatureAlgorithms( data, extensionDataLength );
            case PSK_KEY_EXCHANGE_MODES:
                return parsePskKeyExchangeModes( data, extensionDataLength );
            case RECORD_SIZE_LIMIT:
                return parseRecordSizeLimit( data, extensionDataLength );
            case QUIC_TRANSPORT_PARAMETERS:
                return parseQuicTransportParameters( data, extensionDataLength );
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

    private SupportedVersionsExtensionBase parseSupportedVersions(
            ExtensionCarryingHandshake handshake, ByteBuffer data, int maxLength ) throws MalformedTlsException {
        SupportedVersionsExtensionBase extension;
        if ( handshake instanceof ClientHello ) {
            int versionsLength = data.get() & 0xff;
            ProtocolVersion[] versions = new ProtocolVersion[
                    versionsLength / 2 /* because each ProtocolVersion is encoded as uint16 */];
            for ( int i = 0; i < versions.length; i++ ) {
                versions[i] = parseProtocolVersion( data );
            }
            extension = new ClientSupportedVersionsExtension();
            ( (ClientSupportedVersionsExtension)extension ).setVersions( versions );
        }
        else if ( handshake instanceof ServerHello ) {
            ProtocolVersion selectedVersion = parseProtocolVersion( data );
            extension = new ServerSupportedVersionsExtension();
            ( (ServerSupportedVersionsExtension)extension ).setSelectedVersion( selectedVersion );
        }
        else {
            throw new MalformedTlsException( "illegal SUPPORTED_VERSIONS extension in message of type "
                    + handshake.getClass().getSimpleName() );
        }

        return extension;
    }

    private SignatureAlgorithmsExtension parseSignatureAlgorithms(
            ByteBuffer data, int maxLength ) throws MalformedTlsException {
        int supportedSignatureAlgorithmsLength = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
        SignatureScheme[] supportedSignatureAlgorithms = new SignatureScheme[
                supportedSignatureAlgorithmsLength / 2 /* because SignatureScheme is encoded as uint16*/];
        for ( int i = 0; i < supportedSignatureAlgorithms.length; i++ ) {
            int signatureSchemeRaw = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
            SignatureScheme signatureScheme = SignatureScheme.findByValue( signatureSchemeRaw );
            if ( signatureScheme == null ) {
                throw new MalformedTlsException( "Illegal SignatureScheme.value: " + signatureSchemeRaw );
            }
            supportedSignatureAlgorithms[i] = signatureScheme;
        }
        SignatureAlgorithmsExtension extension = new SignatureAlgorithmsExtension();
        extension.setSupportedSignatureAlgorithms( supportedSignatureAlgorithms );
        return extension;
    }

    private PskKeyExchangeModeExtension parsePskKeyExchangeModes(
            ByteBuffer data, int maxLength ) throws MalformedTlsException {
        int keModesLength = data.get() & 0xff;
        PskKeyExchangeMode[] keModes = new PskKeyExchangeMode[keModesLength /* because PKEM is encoded as uint8 */];
        for ( int i = 0; i < keModesLength; i++ ) {
            int keModeRaw = data.get() & 0xff;
            PskKeyExchangeMode keMode = PskKeyExchangeMode.findByValue( keModeRaw );
            if ( keMode == null ) {
                throw new MalformedTlsException( "Illegal PskKeyExchangeMode.value: " + keModeRaw );
            }
            keModes[i] = keMode;
        }

        PskKeyExchangeModeExtension extension = new PskKeyExchangeModeExtension();
        extension.setKeyExchangeModes( keModes );
        return extension;
    }

    private RecordSizeLimitExtension parseRecordSizeLimit(
            ByteBuffer data, int maxLength ) {
        int recordSizeLimit = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
        RecordSizeLimitExtension extension = new RecordSizeLimitExtension();
        extension.setRecordSizeLimit( recordSizeLimit );
        return extension;
    }

    private QuicTransportParametersExtension parseQuicTransportParameters(
            ByteBuffer data, int maxLength ) throws MalformedTlsException {
        TransportParameterCollectionImpl collection = new TransportParameterCollectionImpl();

        while ( maxLength > 0 ) {
            VariableLengthInteger typeRaw = VariableLengthInteger.decode( data );
            if ( typeRaw == null ) {
                throw new MalformedTlsException( "Malformed VariableLengthInteger TransportParameterType.value" );
            }
            TransportParameterType type = TransportParameterType.findByValue( (int)typeRaw.getValue() );
            if ( type == null ) {
                throw new MalformedTlsException( "Invalid TransportParameterType.value: " + typeRaw );
            }
            VariableLengthInteger length = VariableLengthInteger.decode( data );
            if ( length == null ) {
                throw new MalformedTlsException( "Malformed VariableLengthInteger length of TransportParameter" );
            }

            TransportParameter<?> parameter;
            switch ( type ) {
                case ORIGINAL_DESTINATION_CONNECTION_ID: // fall-through
                case INITIAL_SOURCE_CONNECTION_ID: // fall-through
                case RETRY_SOURCE_CONNECTION_ID: // fall-through
                case STATELESS_RESET_TOKEN: {
                    byte[] value = new byte[(int)length.getValue()];
                    data.get( value );
                    parameter = new ByteArrayTransportParameterImpl( type, value );
                }
                break;
                case MAX_IDLE_TIMEOUT: // fall-through
                case MAX_UDP_PAYLOAD_SIZE: // fall-through
                case INITIAL_MAX_DATA: // fall-through
                case INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: // fall-through
                case INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: // fall-through
                case INITIAL_MAX_STREAM_DATA_UNI: // fall-through
                case INITIAL_MAX_STREAMS_BIDI: // fall-through
                case INITIAL_MAX_STREAMS_UNI: // fall-through
                case ACK_DELAY_EXPONENT: // fall-through
                case MAX_ACK_DELAY: // fall-through
                case ACTIVE_CONNECTION_ID_LIMIT: {
                    long value = VariableLengthIntegerEncoder.decode( data );
                    parameter = new IntegerTransportParameterImpl( type, value );
                }
                break;
                case DISABLE_ACTIVE_MIGRATION: {
                    parameter = new FlagTransportParameterImpl( type, true );
                }
                break;
                case PREFERRED_ADDRESS: {
                    PreferredAddress value = parsePreferredAddress( data, (int)length.getValue() );
                    parameter = new PreferredAddressTransportParameterImpl( type, value );
                }
                break;
                default:
                    throw new MalformedTlsException( "Unimplemented TransportParameterType: " + type );
            }
            maxLength -= typeRaw.getEncodedLengthInBytes() + length.getValue() + length.getEncodedLengthInBytes();
            collection.setParameter( parameter );
        }

        QuicTransportParametersExtension extension = new QuicTransportParametersExtension();
        extension.setTransportParameters( collection );
        return extension;
    }

    // supportive methods...

    private PreferredAddress parsePreferredAddress( ByteBuffer data, int maxLength ) {
        PreferredAddressImpl preferredAddress = new PreferredAddressImpl();
        byte[] ipv4Address = new byte[4];
        data.get( ipv4Address );
        // Spec: "Servers MAY choose to only send a preferred address
        //      of one address family by sending an all-zero address and port
        //      (0.0.0.0:0 or ::.0) for the other family.  IP addresses are
        //      encoded in network byte order." Page 125
        if ( NOT_ONLY_ZEROS.validate( ipv4Address ) ) {
            preferredAddress.setIpv4Address( ipv4Address );
        }
        preferredAddress.setIpv4Port( (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 ) );

        byte[] ipv6Address = new byte[16];
        data.get( ipv6Address );
        if ( NOT_ONLY_ZEROS.validate( ipv6Address ) ) {
            preferredAddress.setIpv6Address( ipv6Address );
        }
        preferredAddress.setIpv6Port( (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 ) );

        int connectionIdSize = data.get() & 0xff;
        byte[] connectionIdRaw = new byte[connectionIdSize];
        data.get( connectionIdRaw );
        // Spec: "contain an alternative connection ID that has a sequence number of 1; see Section 5.1.1" Page 126
        preferredAddress.setConnectionId( new ConnectionIdImpl( connectionIdRaw, VariableLengthInteger.ONE ) );

        byte[] statelessResetTokenRaw = new byte[16];
        data.get( statelessResetTokenRaw );
        preferredAddress.setStatelessResetToken( new StatelessResetTokenImpl( statelessResetTokenRaw ) );

        return preferredAddress;
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

    private ProtocolVersion parseProtocolVersion( ByteBuffer data ) throws MalformedTlsException {
        int protocolVersionRaw = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
        ProtocolVersion protocolVersion = ProtocolVersion.findByValue( protocolVersionRaw );
        if ( protocolVersion == null ) {
            throw new MalformedTlsException( "Invalid ProtocolVersion.value: " + protocolVersionRaw );
        }
        return protocolVersion;
    }
}
