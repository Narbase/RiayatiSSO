package com.narbase.narnic.sso

import org.joda.time.Duration
import java.io.File
import java.util.*

/*
 * Copyright 2017-2024 Narbase technologies and contributors. Use of this source code is governed by the MIT License.
 */
fun main() {
    setSystemProperties()
    RiayatiSsoTester.runTest()
}

/**
 * Used to remove &#13; and &#xD; from the generated SAML response
 */
private fun setSystemProperties() {
    System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true")
    System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true")
}

object RiayatiSsoTester {
    fun runTest() {

        val certPublic = File("/path/to/public/cert.pem")
        val certPrivate = File("/path/to/public/private.pem")

        val clientId = "CLIENT_ID"
        val clientSecret = "CLIENT_SECRET"
        val clinicianId = "CLINICIAN_ID"
        val patientMrn = "PATIENT_MRN"
        val patientMrnAuthority = "PATIENT_MRN_AUTHORITY"
        val assertionId = UUID.randomUUID()

        val token = getToken(clientId, clientSecret, clinicianId)
        val samlResponseGenerator = RiayatiSamlResponseGenerator(certPrivate, certPublic)
        val signed = samlResponseGenerator.getSignedResponse(
            assertionId,
            clinicianId,
            RiayatiSamlResponseGenerator.Role.Clinician,
            Duration.standardMinutes(10)
        )
        println("Signed")
        println(signed)
        println("Sending get SSO")
        val samlBase64 = Base64.getEncoder().encodeToString(signed.encodeToByteArray())
        getSso(clientId, token, patientMrn, patientMrnAuthority, clinicianId, samlBase64)
    }

    @Suppress("UNUSED_PARAMETER", "SameParameterValue")
    /**
     * Implement to call Riayati endpoint `/api/riayati/auth/token` to get the token using the clientId, clientSecret, and clinicianId
     */
    private fun getToken(clientId: String, clientSecret: String, clinicianId: String): String = "TEST_TOKEN"

    @Suppress("UNUSED_PARAMETER", "SameParameterValue")
    /**
     * Implement to call Riayati endpoint `/RiayatiSSO`
     */
    private fun getSso(
        clientId: String,
        token: String,
        patientMrn: String,
        patientMrnAuthority: String,
        clinicianId: String,
        SAMLResponse: String,
    ): String {
        TODO("Call Riayati server /RiayatiSSO to get the token using the clientId, clientSecret, and clinicianId")
    }
}