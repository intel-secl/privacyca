/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.tpm.endorsement.client.jaxrs;

import com.intel.dcsg.cpg.tls.policy.TlsConnection;
import com.intel.mtwilson.jaxrs2.client.MtWilsonClient;
import com.intel.mtwilson.tpm.endorsement.model.TpmEndorsement;
import com.intel.mtwilson.tpm.endorsement.model.TpmEndorsementCollection;
import com.intel.mtwilson.tpm.endorsement.model.TpmEndorsementFilterCriteria;
import com.intel.mtwilson.tpm.endorsement.model.TpmEndorsementLocator;
import java.util.HashMap;
import java.util.Properties;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * An Endorsement certificate is used to bind an identity or specific security attributes to a TPM.
 * The primary use of an Endorsement certificate is to authenticate device identity when an AIK is issued.
 * This API is used to manage the database CRUD operations of an endorsement certificate of the TPM.

 */
public class TpmEndorsements extends MtWilsonClient {
    
    Logger log = LoggerFactory.getLogger(getClass().getName());

    
    /**
     * Constructor.
     * 
     * @param properties This java properties model must include server connection details for the API client initialization.
     * <pre>
     * mtwilson.api.url - Host Verification Service (HVS) base URL for accessing REST APIs
     * 
     * // basic authentication
     * mtwilson.api.username - Username for API basic authentication with the HVS
     * mtwilson.api.password - Password for API basic authentication with the HVS
     * 
     * <b>Example:</b>
     * Properties properties = new Properties();
     * properties.put(“mtwilson.api.url”, “https://server.com:port/mtwilson/v2”);
     * 
     * // basic authentication
     * properties.put("mtwilson.api.username", "admin");
     * properties.put("mtwilson.api.password", "password");
     * properties.put("mtwilson.api.tls.policy.certificate.sha256", "bfc4884d748eff5304f326f34a986c0b3ff0b3b08eec281e6d08815fafdb8b02");
     * 
     * RolePermissions client = new RolePermissions(properties);
     * </pre>
     * @throws Exception 
     */
    public TpmEndorsements(Properties properties) throws Exception {
        super(properties);
    }

    public TpmEndorsements(Properties properties, TlsConnection tlsConnection) throws Exception {
        super(properties, tlsConnection);
    }
    
     /**
     * Creates a tpm endorsement certificate.
     * @param item The serialized TpmEndorsement java model object represents the content of the request body.
     * <pre>
     *                  hardwareUuid (required)        Hardware UUID of the host associated with the certificate. 
     *                                                 Can be retrieved by calling into the GET method on the host with a specific filter criteria.
     *     
     *                  issuer  (required)             The OEM of the TPM. Refer to sample issuer input for attributes.
     * 
     *                  revoked (required)             Validity status of the EK certificate.  
     *                  
     *                  certificate (required)         The Endorsement Certificate of the TPM.Encoded certificate without BEGIN and END in certificate input.
     * 
     *                  comment    (optional)          Comments for the certificate. 
     * </pre>
     * 
     * @return  The serialized TpmEndorsementCollection java model object that was created with collection of tpm endorsements each containing:
     * <pre>
     *             id
     *             hardware_uuid
     *             issuer
     *             revoked
     *             certificate
     *             comment
     * </pre>
     * @since ISecl 1.0
     * @mtwRequiresPermissions tpm_endorsements:create
     * @mtwContentTypeReturned JSON/XML/YAML
     * @mtwMethodType POST
     * @mtwSampleRestCall
     * <pre>
     * https://server.com:8443/mtwilson/v2/tpm-endorsements
     * Input: 
     * {
     *         "hardware_uuid" : "0002bfac-9ac5-e711-906e-00163566263e",
     *         "issuer"        : "C=DE,O=Infineon Technologies AG,OU=OPTIGA(TM) TPM2.0,CN=Infineon OPTIGA(TM) RSA Manufacturing CA 007",
     *         "revoked"       : false,
     *         "certificate"   : "MIIEnDCCA4SgAwIBAgIEUilBVDANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRl
     *                           2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUl
     *                           NBIE1hbnVmYWN0dXJpbmcgQ0EgMDA3MB4XDTE1MTIyMjEzMDUzMFoXDTMwMTIyMjEzMDUzMFowADCCASIwDQYJKoZIhvcNAQE
     *                           BBQADggEPADCCAQoCggEBAJCi7C7RPvUKJGVhQwE0cbC9mX5d2LlIwj/G/DpVO8qBzPdCOBahqezogz9jirvoSQulNAIrm70Y
     *                           cKhZcIr5Ha2C5in7ZvOknRyC5UN94v8KVdLt6c/E/D+C3q+trrKlT0EOlowV3cKF3UpmuTqIpWlKHtYZZcIFTbC5LrWz6eUGk
     *                           gzPg3/L5uxAUs2l6gnSebV0Z7SeWmVW0/aml+HIUv49c+rZ6GLl7eWVrLazUoF6qJ2gqABexwgMhusu4fZW3mnGt0BoJkFWU1
     *                           cz1Rs7FQVD2UYcPpBzIucR4aNPfluKwMnIw/TZFF/jsUsIw1H4asSefrzkd++mmrQWLCzeXmECAwEAAaOCAZgwggGUMFsGCCs
     *                           GAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDcvT3B0aWdh
     *                           UnNhTWZyQ0EwMDcuY3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwM
     *                           DEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUCAwwHaWQ6MDcyODAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJME
     *                           cwRaBDoEGGP2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDA3L09wdGlnYVJzYU1mckNBMDA3LmNybDA
     *                           VBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFJx99akcPUm75zeNSroS/454otdcMBAGA1UdJQQJMAcGBWeBBQgB
     *                           MCEGA1UdCQQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAF92gr1VZ4GbVJ0bVZ1JSkwJ+
     *                           ElshoXPRuuRPuIR+Khj6LFVeEJTt90RXYyRqTTt88hQK8ZXdbwHcAJ/t1tLyzJ50hCnnKj5TgxGf1NDGag4U42/QdlW7e/SFS
     *                           AmMqhfOSxvGqES9hkRgYCIYIdfD6DHsfMjl1js7M9jEh8hSscy3/Dwg8wMeUAJsBBYzWbFEWAd3aLvmW1UW/NTD/IHIV5knOb
     *                           StF8XQgyE74TJWSt7AyQ/fphKMXy63YUJD2sg4sxTQTnh7lIQNmCfbn3/9iR1erX3zoTIM9+Wlwsw0RFxD/SNN5thNhOS1bkE
     *                           8zPZFJB4/jCrljcfjkHpsY77Qf+c=",
     *         "comment"       : "registered by trust agent"
     * }
     * 
     * Output:
     * {
     *         "id"            : "35adea3b-9f35-4e15-8c82-dee2f8880599",
     *         "hardware_uuid" : "0002bfac-9ac5-e711-906e-00163566263e",
     *         "issuer"        : "C=DE,O=Infineon Technologies AG,OU=OPTIGA(TM) TPM2.0,CN=Infineon OPTIGA(TM) RSA Manufacturing CA 007",
     *         "revoked"       : false,
     *         "certificate"   : "MIIEnDCCA4SgAwIBAgIEUilBVDANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRl
     *                           2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUl
     *                           NBIE1hbnVmYWN0dXJpbmcgQ0EgMDA3MB4XDTE1MTIyMjEzMDUzMFoXDTMwMTIyMjEzMDUzMFowADCCASIwDQYJKoZIhvcNAQE
     *                           BBQADggEPADCCAQoCggEBAJCi7C7RPvUKJGVhQwE0cbC9mX5d2LlIwj/G/DpVO8qBzPdCOBahqezogz9jirvoSQulNAIrm70Y
     *                           cKhZcIr5Ha2C5in7ZvOknRyC5UN94v8KVdLt6c/E/D+C3q+trrKlT0EOlowV3cKF3UpmuTqIpWlKHtYZZcIFTbC5LrWz6eUGk
     *                           gzPg3/L5uxAUs2l6gnSebV0Z7SeWmVW0/aml+HIUv49c+rZ6GLl7eWVrLazUoF6qJ2gqABexwgMhusu4fZW3mnGt0BoJkFWU1
     *                           cz1Rs7FQVD2UYcPpBzIucR4aNPfluKwMnIw/TZFF/jsUsIw1H4asSefrzkd++mmrQWLCzeXmECAwEAAaOCAZgwggGUMFsGCCs
     *                           GAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDcvT3B0aWdh
     *                           UnNhTWZyQ0EwMDcuY3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwM
     *                           DEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUCAwwHaWQ6MDcyODAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJME
     *                           cwRaBDoEGGP2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDA3L09wdGlnYVJzYU1mckNBMDA3LmNybDA
     *                           VBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFJx99akcPUm75zeNSroS/454otdcMBAGA1UdJQQJMAcGBWeBBQgB
     *                           MCEGA1UdCQQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAF92gr1VZ4GbVJ0bVZ1JSkwJ+
     *                           ElshoXPRuuRPuIR+Khj6LFVeEJTt90RXYyRqTTt88hQK8ZXdbwHcAJ/t1tLyzJ50hCnnKj5TgxGf1NDGag4U42/QdlW7e/SFS
     *                           AmMqhfOSxvGqES9hkRgYCIYIdfD6DHsfMjl1js7M9jEh8hSscy3/Dwg8wMeUAJsBBYzWbFEWAd3aLvmW1UW/NTD/IHIV5knOb
     *                           StF8XQgyE74TJWSt7AyQ/fphKMXy63YUJD2sg4sxTQTnh7lIQNmCfbn3/9iR1erX3zoTIM9+Wlwsw0RFxD/SNN5thNhOS1bkE
     *                           8zPZFJB4/jCrljcfjkHpsY77Qf+c=",
     *         "comment"       : "registered by trust agent"
     * }
     * </pre>
     * @mtwSampleApiCall
     * <pre>
     * // Create the tpm endorsement model and set hardware_uuid , certificate, issuer ,revoked and comment
     * TpmEndorsement item = new TpmEndorsement();
     * item.setHardwareUuid("0002bfac-9ac5-e711-906e-00163566263e");
     * item.setCertificate(certificate.getEncoded());
     * item.setIssuer("C=DE,O=Infineon Technologies AG,OU=OPTIGA(TM) TPM2.0,CN=Infineon OPTIGA(TM) RSA Manufacturing CA 007");
     * item.setRevoked(false);
     * item.setComment("registered by trust agent");
     * 
     * // Create the client and call the create API
     * TpmEndorsements client = new TpmEndorsements(properties);
     * TpmEndorsementCollection collection = client.createTpmEndorsements(item);
     * </pre>
     */
    public TpmEndorsement createTpmEndorsement(TpmEndorsement item) {
        log.debug("target: {}", getTarget().getUri().toString());
        TpmEndorsement newObj = getTarget().path("tpm-endorsements").request().accept(MediaType.APPLICATION_JSON).post(Entity.json(item), TpmEndorsement.class);
        return newObj;
    }
    
    /**
     * Deletes a tpm endorsement certificate.
     * @param locator The content models of the TpmEndorsementLocator java model object can be used as path parameter.
     * <pre>
     *                      id (required)         Tpm endorsement ID specified as a path parameter.
     * </pre>
     * @since ISecL 1.0
     * @mtwRequiresPermissions tpm_endorsements:delete
     * @mtwContentTypeReturned N/A
     * @mtwMethodType DELETE
     * @mtwSampleRestCall
     * <pre>
     *  https://server.com:8443/mtwilson/v2/tpm-endorsements/3e75091f-4657-496c-a721-8a77931ee9da
     *  Output: 204 No content
     * </pre>
     * @mtwSampleApiCall
     * <pre>
     *   // Create the tpm endorsement locator model and set the locator id
     * TpmEndorsementLocator locator =  new TpmEndorsementLocator();
     * locator.id=UUID.valueOf("93d153c7-1e84-4dba-bc01-bff72dc9bc40");
     * 
     * // Create the client and call the delete API
     * TpmEndorsements client = new TpmEndorsements(properties);
     * client.delete(locator);
     * </pre>
     */
    public void delete(TpmEndorsementLocator locator) {
        log.debug("target: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", locator.id);
        Response obj = getTarget().path("tpm-endorsements/{id}").resolveTemplates(map).request(MediaType.APPLICATION_JSON).delete();
        if( !obj.getStatusInfo().getFamily().equals(Response.Status.Family.SUCCESSFUL)) {
            throw new WebApplicationException("Delete TpmEndorsement failed");
        }
    }
     /**
     * Update tpm endorsement certificate.
     * @param item The serialized TpmEndorsement java model object represents the content of the request body.
     * <pre>
     *           hardwareUuid (required)        Hardware UUID of the host associated with the certificate. 
     *                                          Can be retrieved by calling into the GET method on the host with a specific filter criteria.
     * 
     *           issuer  (required)             The OEM of the TPM.
     * 
     *           revoked (required)             Validity status of the EK certificate.  
     * 
     *           certificate (required)         The EK Certificate of the TPM.
     * 
     *           comment    (optional)          Comments for the certificate. 
     * </pre>
     * @since ISecL 1.0
     * @mtwRequiresPermissions tpm_endorsements:store
     * @mtwContentTypeReturned JSON/XML/YAML
     * @mtwMethodType PUT
     * @mtwSampleRestCall
     * <pre> 
     * https://server.com:8443/mtwilson/v2/tpm-endorsements/ebec68d1-a78f-4b66-b643-d80ba44e7fc0
     * Input: 
     * {
     *         "hardware_uuid" : "0002bfac-9ac5-e711-906e-00163566263e",
     *         "issuer"        : "C=DE,O=Infineon Technologies AG,OU=OPTIGA(TM) TPM2.0,CN=Infineon OPTIGA(TM) RSA Manufacturing CA 007",
     *         "revoked"       : false,
     *         "certificate"   : "MIIEnDCCA4SgAwIBAgIEUilBVDANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRl
     *                           2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUl
     *                           NBIE1hbnVmYWN0dXJpbmcgQ0EgMDA3MB4XDTE1MTIyMjEzMDUzMFoXDTMwMTIyMjEzMDUzMFowADCCASIwDQYJKoZIhvcNAQE
     *                           BBQADggEPADCCAQoCggEBAJCi7C7RPvUKJGVhQwE0cbC9mX5d2LlIwj/G/DpVO8qBzPdCOBahqezogz9jirvoSQulNAIrm70Y
     *                           cKhZcIr5Ha2C5in7ZvOknRyC5UN94v8KVdLt6c/E/D+C3q+trrKlT0EOlowV3cKF3UpmuTqIpWlKHtYZZcIFTbC5LrWz6eUGk
     *                           gzPg3/L5uxAUs2l6gnSebV0Z7SeWmVW0/aml+HIUv49c+rZ6GLl7eWVrLazUoF6qJ2gqABexwgMhusu4fZW3mnGt0BoJkFWU1
     *                           cz1Rs7FQVD2UYcPpBzIucR4aNPfluKwMnIw/TZFF/jsUsIw1H4asSefrzkd++mmrQWLCzeXmECAwEAAaOCAZgwggGUMFsGCCs
     *                           GAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDcvT3B0aWdh
     *                           UnNhTWZyQ0EwMDcuY3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwM
     *                           DEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUCAwwHaWQ6MDcyODAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJME
     *                           cwRaBDoEGGP2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDA3L09wdGlnYVJzYU1mckNBMDA3LmNybDA
     *                           VBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFJx99akcPUm75zeNSroS/454otdcMBAGA1UdJQQJMAcGBWeBBQgB
     *                           MCEGA1UdCQQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAF92gr1VZ4GbVJ0bVZ1JSkwJ+
     *                           ElshoXPRuuRPuIR+Khj6LFVeEJTt90RXYyRqTTt88hQK8ZXdbwHcAJ/t1tLyzJ50hCnnKj5TgxGf1NDGag4U42/QdlW7e/SFS
     *                           AmMqhfOSxvGqES9hkRgYCIYIdfD6DHsfMjl1js7M9jEh8hSscy3/Dwg8wMeUAJsBBYzWbFEWAd3aLvmW1UW/NTD/IHIV5knOb
     *                           StF8XQgyE74TJWSt7AyQ/fphKMXy63YUJD2sg4sxTQTnh7lIQNmCfbn3/9iR1erX3zoTIM9+Wlwsw0RFxD/SNN5thNhOS1bkE
     *                           8zPZFJB4/jCrljcfjkHpsY77Qf+c=",
     *         "comment"       : "registered by trust agent"
     * }
     * 
     * Output:
     * {
     *         "id"            : "35adea3b-9f35-4e15-8c82-dee2f8880599",
     *         "hardware_uuid" : "0002bfac-9ac5-e711-906e-00163566263e",
     *         "issuer"        : "C=DE,O=Infineon Technologies AG,OU=OPTIGA(TM) TPM2.0,CN=Infineon OPTIGA(TM) RSA Manufacturing CA 007",
     *         "revoked"       : false,
     *         "certificate"   : "MIIEnDCCA4SgAwIBAgIEUilBVDANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRl
     *                           2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUl
     *                           NBIE1hbnVmYWN0dXJpbmcgQ0EgMDA3MB4XDTE1MTIyMjEzMDUzMFoXDTMwMTIyMjEzMDUzMFowADCCASIwDQYJKoZIhvcNAQE
     *                           BBQADggEPADCCAQoCggEBAJCi7C7RPvUKJGVhQwE0cbC9mX5d2LlIwj/G/DpVO8qBzPdCOBahqezogz9jirvoSQulNAIrm70Y
     *                           cKhZcIr5Ha2C5in7ZvOknRyC5UN94v8KVdLt6c/E/D+C3q+trrKlT0EOlowV3cKF3UpmuTqIpWlKHtYZZcIFTbC5LrWz6eUGk
     *                           gzPg3/L5uxAUs2l6gnSebV0Z7SeWmVW0/aml+HIUv49c+rZ6GLl7eWVrLazUoF6qJ2gqABexwgMhusu4fZW3mnGt0BoJkFWU1
     *                           cz1Rs7FQVD2UYcPpBzIucR4aNPfluKwMnIw/TZFF/jsUsIw1H4asSefrzkd++mmrQWLCzeXmECAwEAAaOCAZgwggGUMFsGCCs
     *                           GAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDcvT3B0aWdh
     *                           UnNhTWZyQ0EwMDcuY3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwM
     *                           DEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUCAwwHaWQ6MDcyODAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJME
     *                           cwRaBDoEGGP2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDA3L09wdGlnYVJzYU1mckNBMDA3LmNybDA
     *                           VBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFJx99akcPUm75zeNSroS/454otdcMBAGA1UdJQQJMAcGBWeBBQgB
     *                           MCEGA1UdCQQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAF92gr1VZ4GbVJ0bVZ1JSkwJ+
     *                           ElshoXPRuuRPuIR+Khj6LFVeEJTt90RXYyRqTTt88hQK8ZXdbwHcAJ/t1tLyzJ50hCnnKj5TgxGf1NDGag4U42/QdlW7e/SFS
     *                           AmMqhfOSxvGqES9hkRgYCIYIdfD6DHsfMjl1js7M9jEh8hSscy3/Dwg8wMeUAJsBBYzWbFEWAd3aLvmW1UW/NTD/IHIV5knOb
     *                           StF8XQgyE74TJWSt7AyQ/fphKMXy63YUJD2sg4sxTQTnh7lIQNmCfbn3/9iR1erX3zoTIM9+Wlwsw0RFxD/SNN5thNhOS1bkE
     *                           8zPZFJB4/jCrljcfjkHpsY77Qf+c=",
     *         "comment"       : "registered by trust agent"
     * }
     * </pre>
     * @mtwSampleApiCall
     * <pre>
     * // Create the tpm endorsement model and set a id, hardwareuuid, certificate , issuer , comment
     * TpmEndorsement item = new TpmEndorsement();
     * item.setId(UUID.valueOf("1e757b23-17c6-45df-866f-4b0e2b8543aa"));
     * item.setHardwareUuid(new UUID().toString());
     * item.setCertificate(certificate.getEncoded());
     * item.setIssuer("C=DE,O=Infineon Technologies AG,OU=OPTIGA(TM) TPM2.0,CN=Infineon OPTIGA(TM) RSA Manufacturing CA 007");
     * item.setRevoked(true);
     * item.setComment("Updated");
     * // Create the client and call the update API
     * TpmEndorsements client = new TpmEndorsements(properties);
     * client.store(item)
     * </pre>
     */
    public void store(TpmEndorsement item) {
        log.debug("target: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", item.getId().toString());
        getTarget().path("tpm-endorsements/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).put(Entity.json(item), TpmEndorsement.class);
        
    }
    
     /**
     * Retrieves a tpm endorsement certificate.
     * @param locator - The content models of the TpmEndorsementLocator java model object can be used as path and query parameters.
     * <pre>
     *          id (required)       Tpm endorsement ID specified as a path parameter.
     * </pre>
     * @return The serialized TpmEndorsement java model object that was retrieved:
     * <pre>
     *      id
     *      hardware_uuid
     *      issuer
     *      revoked
     *      certificate 
     *      comment
     * </pre>
     * @since ISecL 1.0
     * @mtwRequiresPermissions tpm_endorsements:retrieve
     * @mtwContentTypeReturned JSON/XML/YAML
     * @mtwMethodType GET
     * @mtwSampleRestCall
     * <pre>
     * https://server.com:8443/mtwilson/v2/tpm-endorsements/d7e24dd4-76c0-4384-a8b0-09552ebaa1a1
     * output: 
     * {
     *      "tpm_endorsements": [
     *          {
     *              "id"            : "d7e24dd4-76c0-4384-a8b0-09552ebaa1a1",
     *              "hardware_uuid" : "80e54342-94f2-e711-906e-001560a04062",
     *              "issuer"        : "C=DE,O=Infineon Technologies AG,OU=OPTIGA(TM) TPM2.0,CN=Infineon OPTIGA(TM) RSA Manufacturing CA 007",
     *              "revoked"       : false,
     *              "certificate"   : "MIIEnDCCA4SgAwIBAgIEUilBVDANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRl
     *                                2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUl
     *                                NBIE1hbnVmYWN0dXJpbmcgQ0EgMDA3MB4XDTE1MTIyMjEzMDUzMFoXDTMwMTIyMjEzMDUzMFowADCCASIwDQYJKoZIhvcNAQE
     *                                BBQADggEPADCCAQoCggEBAJCi7C7RPvUKJGVhQwE0cbC9mX5d2LlIwj/G/DpVO8qBzPdCOBahqezogz9jirvoSQulNAIrm70Y
     *                                cKhZcIr5Ha2C5in7ZvOknRyC5UN94v8KVdLt6c/E/D+C3q+trrKlT0EOlowV3cKF3UpmuTqIpWlKHtYZZcIFTbC5LrWz6eUGk
     *                                gzPg3/L5uxAUs2l6gnSebV0Z7SeWmVW0/aml+HIUv49c+rZ6GLl7eWVrLazUoF6qJ2gqABexwgMhusu4fZW3mnGt0BoJkFWU1
     *                                cz1Rs7FQVD2UYcPpBzIucR4aNPfluKwMnIw/TZFF/jsUsIw1H4asSefrzkd++mmrQWLCzeXmECAwEAAaOCAZgwggGUMFsGCCs
     *                                GAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDcvT3B0aWdh
     *                                UnNhTWZyQ0EwMDcuY3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwM
     *                                DEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUCAwwHaWQ6MDcyODAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJME
     *                                cwRaBDoEGGP2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDA3L09wdGlnYVJzYU1mckNBMDA3LmNybDA
     *                                VBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFJx99akcPUm75zeNSroS/454otdcMBAGA1UdJQQJMAcGBWeBBQgB
     *                                MCEGA1UdCQQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAF92gr1VZ4GbVJ0bVZ1JSkwJ+
     *                                ElshoXPRuuRPuIR+Khj6LFVeEJTt90RXYyRqTTt88hQK8ZXdbwHcAJ/t1tLyzJ50hCnnKj5TgxGf1NDGag4U42/QdlW7e/SFS
     *                                AmMqhfOSxvGqES9hkRgYCIYIdfD6DHsfMjl1js7M9jEh8hSscy3/Dwg8wMeUAJsBBYzWbFEWAd3aLvmW1UW/NTD/IHIV5knOb
     *                                StF8XQgyE74TJWSt7AyQ/fphKMXy63YUJD2sg4sxTQTnh7lIQNmCfbn3/9iR1erX3zoTIM9+Wlwsw0RFxD/SNN5thNhOS1bkE
     *                                8zPZFJB4/jCrljcfjkHpsY77Qf+c=",
     *              "comment"       : "registered by trust agent"
     *          }
     *      ]
     *  }
     * </pre>
     * @mtwSampleApiCall
     * <pre>
     * // Create the tpm endorsement locator model and set the locator id
     * TpmEndorsementLocator locator =  new TpmEndorsementLocator();
     * locator.id=UUID.valueOf("27517e2b-7398-481e-86b3-186d39ef9b0a");
     *  //Create the client and call the retrieve API
     * TpmEndorsements client = new TpmEndorsements(properties);
     * TpmEndorsement tpmEndorsement = client.retrieve(locator);
     * </pre>
     */
    public TpmEndorsement retrieve(TpmEndorsementLocator locator) {
        log.debug("target: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", locator.id);
        TpmEndorsement obj = getTarget().path("tpm-endorsements/{id}").resolveTemplates(map).request(MediaType.APPLICATION_JSON).get(TpmEndorsement.class);
        return obj;
    }
    
    /**
     * Searches for tpm endorsement certificate.
     * @param criteria The content models of the TpmEndorsementFilterCriteria java model object can be used as query parameters.
     * <pre>
     *          filter                    Boolean value to indicate whether the response should be filtered to return no 
     *                                    results instead of listing all flavor groups. Default value is true.
     *          
     *          id                        Tpm endorsement ID.
     * 
     *          hardwareUuidEqualTo       hardware UUID of the host to which the Ek is associated.
     *  
     *          issuerEqualTo             Issuer name.
     * 
     *          issuerContains            Substring of issuer name.
     *          
     *          revokedEqualTo            Revoked status of the certificate.
     *          
     *          commentEqualTo            The compelete comment associted with the EK. 
     *          
     *          commentContains           Substring of comment associated with the EK.
     * </pre>
     * @return The serialized TpmEndorsementCollection java model object that was searched : 
     * <pre>
     *              id 
     *              hardware_uuid 
     *              issuer 
     *              revoked 
     *              certificate 
     *              comment
     * </pre>
     * @since ISecL 1.0
     * @mtwRequiresPermissions tpm_endorsements:search
     * @mtwContentTypeReturned JSON/XML/YAML
     * @mtwMethodType GET
     * @mtwSampleRestCall
     * <pre>
     * https://server.com:8443/mtwilson/v2/tpm-endorsements?id=d7e24dd4-76c0-4384-a8b0-09552ebaa1a1
     * Output: 
     * {
     *      "tpm_endorsements": [
     *          {
     *              "id"            : "d7e24dd4-76c0-4384-a8b0-09552ebaa1a1",
     *              "hardware_uuid" : "80e54342-94f2-e711-906e-001560a04062",
     *              "issuer"        : "C=DE,O=Infineon Technologies AG,OU=OPTIGA(TM) TPM2.0,CN=Infineon OPTIGA(TM) RSA Manufacturing CA 007",
     *              "revoked"       : false,
     *              "certificate"   : "MIIEnDCCA4SgAwIBAgIEUilBVDANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRl
     *                                2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUl
     *                                NBIE1hbnVmYWN0dXJpbmcgQ0EgMDA3MB4XDTE1MTIyMjEzMDUzMFoXDTMwMTIyMjEzMDUzMFowADCCASIwDQYJKoZIhvcNAQE
     *                                BBQADggEPADCCAQoCggEBAJCi7C7RPvUKJGVhQwE0cbC9mX5d2LlIwj/G/DpVO8qBzPdCOBahqezogz9jirvoSQulNAIrm70Y
     *                                cKhZcIr5Ha2C5in7ZvOknRyC5UN94v8KVdLt6c/E/D+C3q+trrKlT0EOlowV3cKF3UpmuTqIpWlKHtYZZcIFTbC5LrWz6eUGk
     *                                gzPg3/L5uxAUs2l6gnSebV0Z7SeWmVW0/aml+HIUv49c+rZ6GLl7eWVrLazUoF6qJ2gqABexwgMhusu4fZW3mnGt0BoJkFWU1
     *                                cz1Rs7FQVD2UYcPpBzIucR4aNPfluKwMnIw/TZFF/jsUsIw1H4asSefrzkd++mmrQWLCzeXmECAwEAAaOCAZgwggGUMFsGCCs
     *                                GAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDcvT3B0aWdh
     *                                UnNhTWZyQ0EwMDcuY3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwM
     *                                DEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUCAwwHaWQ6MDcyODAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJME
     *                                cwRaBDoEGGP2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDA3L09wdGlnYVJzYU1mckNBMDA3LmNybDA
     *                                VBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFJx99akcPUm75zeNSroS/454otdcMBAGA1UdJQQJMAcGBWeBBQgB
     *                                MCEGA1UdCQQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAF92gr1VZ4GbVJ0bVZ1JSkwJ+
     *                                ElshoXPRuuRPuIR+Khj6LFVeEJTt90RXYyRqTTt88hQK8ZXdbwHcAJ/t1tLyzJ50hCnnKj5TgxGf1NDGag4U42/QdlW7e/SFS
     *                                AmMqhfOSxvGqES9hkRgYCIYIdfD6DHsfMjl1js7M9jEh8hSscy3/Dwg8wMeUAJsBBYzWbFEWAd3aLvmW1UW/NTD/IHIV5knOb
     *                                StF8XQgyE74TJWSt7AyQ/fphKMXy63YUJD2sg4sxTQTnh7lIQNmCfbn3/9iR1erX3zoTIM9+Wlwsw0RFxD/SNN5thNhOS1bkE
     *                                8zPZFJB4/jCrljcfjkHpsY77Qf+c=",
     *              "comment"       : "registered by trust agent"
     *          }
     *      ]
     *  }
     * </pre>
     * @mtwSampleApiCall
     * <pre>
     * // Create the tpm endorsement filter criteria model and set criteria
     * TpmEndorsementFilterCriteria criteria = new TpmEndorsementFilterCriteria();
     * criteria.revokedEqualTo = false;
     *  // Create the client and call the search API
     * TpmEndorsements client = new TpmEndorsements(properties);
     * TpmEndorsementCollection tpmEndorsementCollection = client.searchTpmEndorsements(criteria);
     * </pre>
     */
    public TpmEndorsementCollection searchTpmEndorsements(TpmEndorsementFilterCriteria criteria) {
        log.debug("target: {}", getTarget().getUri().toString());
        TpmEndorsementCollection objList = getTargetPathWithQueryParams("tpm-endorsements", criteria).request(MediaType.APPLICATION_JSON).get(TpmEndorsementCollection.class);
        return objList;
    }
}
