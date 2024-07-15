package com.narbase.narnic.sso

import com.onelogin.saml2.util.Util
import org.joda.time.DateTime
import org.joda.time.DateTimeZone
import org.joda.time.Duration
import org.opensaml.core.config.InitializationException
import org.opensaml.core.config.InitializationService
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport
import org.opensaml.core.xml.schema.XSString
import org.opensaml.core.xml.schema.impl.XSStringBuilder
import org.opensaml.saml.saml2.core.AttributeValue
import org.opensaml.saml.saml2.core.StatusCode
import org.opensaml.saml.saml2.core.impl.*
import org.opensaml.security.x509.BasicX509Credential
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory
import org.opensaml.xmlsec.signature.impl.SignatureBuilder
import org.opensaml.xmlsec.signature.support.SignatureConstants
import org.opensaml.xmlsec.signature.support.Signer
import java.io.File
import java.io.StringWriter
import java.util.*
import javax.xml.transform.OutputKeys
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult

/*
 * Copyright 2017-2024 Narbase technologies and contributors. Use of this source code is governed by the MIT License.
 */
@Suppress("unused")
class RiayatiSamlResponseGenerator(privateKeyFile: File, publicKeyFile: File) {
    init {
        initialize()
    }

    private val privateKey = Util.loadPrivateKey(privateKeyFile.readText())
    private val cert = Util.loadCert(publicKeyFile.readText())
    private val issuerName = "BalsamMedico"


    private fun initialize() {
        try {
            InitializationService.initialize()
            println("Initialized successfully")
        } catch (e: InitializationException) {
            e.printStackTrace()
            throw e
        }
    }

    fun getSignedResponse(assertionId: UUID, clinicianId: String, role: Role, validity: Duration): String {
        val userRole = role.dtoName
        val issueDate = DateTime.now(DateTimeZone.UTC)
        val validTillDate = issueDate.plus(validity)

        val response = ResponseBuilder().buildObject()
        response.id = UUID.randomUUID().toString()
        response.issueInstant = issueDate

        response.issuer = IssuerBuilder().buildObject().apply {
            this.value = issuerName
        }

        response.status = StatusBuilder().buildObject().apply {
            statusCode = StatusCodeBuilder().buildObject().apply {
                value = StatusCode.SUCCESS
            }
        }

        val assertion = AssertionBuilder().buildObject().apply {
            this.id = assertionId.toString()
            this.issueInstant = issueDate
            this.issuer = IssuerBuilder().buildObject().apply {
                this.value = issuerName
            }
            this.subject = SubjectBuilder().buildObject().apply {
                this.nameID = NameIDBuilder().buildObject().apply {
                    this.format = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
                    this.value = clinicianId
                }
                this.subjectConfirmations.add(SubjectConfirmationBuilder().buildObject().apply {
                    this.method = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
                    this.subjectConfirmationData = SubjectConfirmationDataBuilder().buildObject().apply {
                        this.recipient = "Recipient"
                        this.notOnOrAfter = validTillDate
                    }
                })
            }
            this.conditions = ConditionsBuilder().buildObject().apply {
                this.notBefore = issueDate
                this.notOnOrAfter = validTillDate
            }
            this.authnStatements.add(AuthnStatementBuilder().buildObject().apply {
                this.authnContext = AuthnContextBuilder().buildObject().apply {
                    this.authnContextClassRef = AuthnContextClassRefBuilder().buildObject().apply {
                        this.authnContextClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
                    }
                }
            })
            this.attributeStatements.add(AttributeStatementBuilder().buildObject().apply {
                this.attributes.add(AttributeBuilder().buildObject().apply {
                    this.name = "clinicianId"
                    this.nameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                    this.attributeValues.add(
                        XSStringBuilder().buildObject(
                            AttributeValue.DEFAULT_ELEMENT_NAME,
                            XSString.TYPE_NAME
                        ).apply {
                            this.value = clinicianId
                        })
                })
                this.attributes.add(AttributeBuilder().buildObject().apply {
                    this.name = "urn:oasis:names:tc:xacml:2.0:subject:role"
                    this.nameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                    this.attributeValues.add(
                        XSStringBuilder().buildObject(
                            AttributeValue.DEFAULT_ELEMENT_NAME,
                            XSString.TYPE_NAME
                        ).apply {
                            this.value = userRole
                        })
                })
            })
        }
        response.assertions.add(assertion)

        val credential = BasicX509Credential(cert, privateKey)

        val assertionSignature = SignatureBuilder().buildObject().apply {
            signingCredential = BasicX509Credential(cert, privateKey)
            signatureAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1
            canonicalizationAlgorithm = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS
            keyInfo = X509KeyInfoGeneratorFactory().apply {
                setEmitEntityCertificate(true)
            }.newInstance().generate(credential)

        }

        assertion.signature = assertionSignature

        val responseElement = XMLObjectProviderRegistrySupport
            .getMarshallerFactory()
            .getMarshaller(response)
            ?.marshall(response) ?: throw RuntimeException("Failed to marshal response")
        Signer.signObject(assertionSignature)

        val transformer = TransformerFactory.newInstance().newTransformer()
        val buffer = StringWriter()
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes")
        transformer.transform(DOMSource(responseElement), StreamResult(buffer))

        return buffer.toString()
    }

    enum class Role(val dtoName: String) {
        Clinician("%HS_Clinician"),
        Nurse("%HS_Nurse"),
        NurseBtg("%HS_Nurse_BTG"),
        AlliedHealth("%HS_AlliedHealth"),
    }
}