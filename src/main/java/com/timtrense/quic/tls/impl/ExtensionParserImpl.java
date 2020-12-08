package com.timtrense.quic.tls.impl;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import lombok.NonNull;

import com.timtrense.quic.impl.base.VariableLengthIntegerEncoder;
import com.timtrense.quic.impl.exception.MalformedTlsException;
import com.timtrense.quic.impl.exception.QuicParsingException;
import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;
import com.timtrense.quic.tls.HostName;
import com.timtrense.quic.tls.NameType;
import com.timtrense.quic.tls.NamedGroup;
import com.timtrense.quic.tls.ServerName;
import com.timtrense.quic.tls.extensions.RenegotiationInfoExtension;
import com.timtrense.quic.tls.extensions.ServerNameIndicationExtension;
import com.timtrense.quic.tls.extensions.SupportedGroupsExtension;

/**
 * Default implementation for {@link MessageParser}
 *
 * @author Tim Trense
 */
public class ExtensionParserImpl implements ExtensionParser {

    @Override
    public Extension parseExtension(
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
            // TODO: other cases
            default:
                throw new MalformedTlsException( "Unimplemented TLS handshake message type: " + extensionType.name() );
        }
    }

    private ServerNameIndicationExtension parseServerName( ByteBuffer data, int maxLength ) throws MalformedTlsException {
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

    private SupportedGroupsExtension parseSupportedGroups( ByteBuffer data, int extensionDataLength ) throws MalformedTlsException {
        int namedGroupListLength = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
        // all named group values are 2 bytes wide, so length of the list is half the length in bytes
        namedGroupListLength /= 2;
        NamedGroup[] namedGroupList = new NamedGroup[namedGroupListLength];

        for ( int i = 0; i < namedGroupListLength; i++ ) {
            int value = (int)VariableLengthIntegerEncoder.decodeFixedLengthInteger( data, 2 );
            NamedGroup group = NamedGroup.findByValue( value );
            if ( group == null ) {
                throw new MalformedTlsException( "Invalid NamedGroup.value: " + value );
            }
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
}
