from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import opentype
from pyasn1.type import tag
from pyasn1.type import univ

MAX = float('inf')


def _buildOid(*components):
    output = []
    for x in tuple(components):
        if isinstance(x, univ.ObjectIdentifier):
            output.extend(list(x))
        else:
            output.append(int(x))
    return univ.ObjectIdentifier(output)


cmsContentTypesMap = {}


class CMSVersion(univ.Integer):
    namedValues = namedval.NamedValues(
        ('v0', 0), ('v1', 1), ('v2', 2),
        ('v3', 3), ('v4', 4), ('v5', 5)
    )


class ContentType(univ.ObjectIdentifier):
    pass


class ContentInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('contentType', ContentType()),
        namedtype.NamedType('content', univ.Any().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
                            openType=opentype.OpenType('contentType', cmsContentTypesMap)
                            )
    )


class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Any())
    )


class SubjectKeyIdentifier(univ.OctetString):
    pass


class Name(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('', univ.Any())
    )


class CertificateSerialNumber(univ.Integer):
    pass


class IssuerAndSerialNumber(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuer', Name()),
        namedtype.NamedType('serialNumber', CertificateSerialNumber())
    )


class RecipientIdentifier(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuerAndSerialNumber', IssuerAndSerialNumber()),
        namedtype.NamedType('subjectKeyIdentifier', SubjectKeyIdentifier().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
    )


class EncryptedKey(univ.OctetString):
    pass


class KeyTransRecipientInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', CMSVersion()),
        namedtype.NamedType('rid', RecipientIdentifier()),
        namedtype.NamedType('keyEncryptionAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('encryptedKey', EncryptedKey())
    )


class RecipientInfo(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ktri', KeyTransRecipientInfo())
    )


class RecipientInfos(univ.SetOf):
    componentType = RecipientInfo()
    sizeSpec = constraint.ValueSizeConstraint(1, MAX)


class EncryptedContent(univ.OctetString):
    pass


class EncryptedContentInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('contentType', ContentType()),
        namedtype.NamedType('contentEncryptionAlgorithm', AlgorithmIdentifier()),
        namedtype.OptionalNamedType('encryptedContent', EncryptedContent().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
    )


class Attribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attrType', univ.ObjectIdentifier()),
        namedtype.NamedType('attrValues', univ.SetOf(componentType=univ.Any()))
    )


class UnprotectedAttributes(univ.SetOf):
    componentType = Attribute()
    sizeSpec = constraint.ValueSizeConstraint(1, MAX)


class EnvelopedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', CMSVersion()),
        namedtype.NamedType('recipientInfos', RecipientInfos()),
        namedtype.NamedType('encryptedContentInfo', EncryptedContentInfo()),
        namedtype.OptionalNamedType('unprotectedAttrs', UnprotectedAttributes().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)))
    )


id_envelopedData = _buildOid(1, 2, 840, 113549, 1, 7, 3)
cmsContentTypesMap.update({
    id_envelopedData: EnvelopedData()
})
