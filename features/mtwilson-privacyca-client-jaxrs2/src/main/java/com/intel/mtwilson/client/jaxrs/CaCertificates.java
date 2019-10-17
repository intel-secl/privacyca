/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.client.jaxrs;

import com.intel.mtwilson.jaxrs2.client.MtWilsonClient;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.tls.policy.TlsConnection;
import com.intel.mtwilson.privacyca.v2.model.CaCertificateFilterCriteria;

/**
 * These resources are used to search or retrieve the certificates based on the ID or the domain.
 * <pre>
 * The host verification service maintains different CA certificates for different functionalities. 
 * Some of these certificates are saml, root, privacy, tls etc. 
 * </pre>
 * @author ssbangal
 */
public class CaCertificates extends MtWilsonClient {
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
     * RegisterUsers client = new RegisterUsers(properties);
     * </pre>
     * @throws Exception 
     */
    
    Logger log = LoggerFactory.getLogger(getClass().getName());

    public CaCertificates(URL url) throws Exception{
        super(url);
    }

    public CaCertificates(Properties properties) throws Exception {
        super(properties);
    }
    
    public CaCertificates(Configuration configuration) throws Exception {
        super(configuration);
    }
    public CaCertificates(Properties properties, TlsConnection tlsConnection) throws Exception {
        super(properties, tlsConnection);
    }
        
    /**
     * Retrieves the details of the specified certificate from the system.
     * @param certificateId Id of the certificate being requested. Possible options include "root", "saml", "tls", and "privacy".
     * @return X509Certificate of the requested type.
     * @since Mt.Wilson 2.0
     * @mtwRequiresPermissions None
     * @mtwContentTypeReturned application/x-pem-file
     * @mtwMethodType GET
     * @mtwSampleRestCall
     * <div style="word-wrap: break-word; width: 1024px"><pre>
     * https://server.com:8181/mtwilson/v2/ca-certificates/root
     * 
     * Output: 
     * -----BEGIN CERTIFICATE-----
     * MIIC0zCCAbugAwIBAgIJAP8y0d2XNaa0MA0GCSqGSIb3DQEBCwUAMCkxETAPBgNVBAsTCG10d2ls
     * c29uMRQwEgYDVQQDEwttdHdpbHNvbi1jYTAeFw0xNDA0MjMwNDI0NTdaFw0xNTA0MjMwNDI0NTda
     * MCkxETAPBgNVBAsTCG10d2lsc29uMRQwEgYDVQQDEwttdHdpbHNvbi1jYTCCASIwDQYJKoZIhvcN
     * AQEBBQADggEPADCCAQoCggEBAL6r6DnRdQiuH8uHP/BboABxfwquWwzyX5OY5cjMxfR8RR4XhOi/
     * govUzcFzOotwv6YUM49QVK0c3C4Q5dVuE3EX8PaU7KzCik6DcuMzFdHe4hQzoINIvjDKmW1A3lwp
     * HKEnMTuYkbAnJToEg0G2ZhBX6Ye/kZvLaDpvBF84EJBDjxXKFksLWONyakRXOSLkfIshEvQF6kfz
     * JxCPwxDHAU94svm2Wcl7GLKScr/MUiZxJSIX7GWZSt2LLLq6hQvXXw3XeQCdExmwOipYtAj7JI4u
     * 7lO+bmpQX/UtIGePJCYAtogQ6KbZ+0EnJursdZH2sfJNPuPQ37JOsGf8G6Z+nyUCAwEAATANBgkq
     * hkiG9w0BAQsFAAOCAQEAZbzmOBilsCwCRMakJT//U6kAZLo0DFhBU5ITPz+wGXcO5FcAOMZL3qou
     * YbXL9H7KRMXHa6VcNOOkgoUjrjbOiZtzSWmyVZdjpyeT/9Lct7lLYY+MXMei9SMaiywtLCzAkHf4
     * Ewpl8zaMSjs9baE/18/1SAneyXz6jwrZBua5GJWTDwiZidk3l9MfgRpStYaKXpiian0MTrvp0Lcc
     * 2wzn8esuaBfEx0GGeJQyPDRV3fbpDON9sZRMLjS6pX99XeAdh+qJdjaW9CYsfi40k1vlZRK/Pt2H
     * gkVhnRnidYrMN5Qu4VqEQkd4Gz0jPJW+EfnbM+W/PvlWgDIZvhq7UfpjMA==
     * -----END CERTIFICATE-----
     * </pre></div>
     * @mtwSampleApiCall
     * <div style="word-wrap: break-word; width: 1024px"><pre>
     *  CaCertificates client = new CaCertificates(properties);
     *  X509Certificate rootCertificate = client.retrieveCaCertificate("root");
     *  X509Certificate tlsCertificate = client.retrieveCaCertificate("tls");
     *  X509Certificate samlCertificate = client.retrieveCaCertificate("saml");
     *  X509Certificate privacyCertificate = client.retrieveCaCertificate("privacy");
     * </pre></div>
    */    
    public X509Certificate retrieveCaCertificate(String certificateId) {
        //  {id} can be:  "root", "saml", "tls", "privacy"
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", certificateId);
        X509Certificate certificate = getTargetPath("ca-certificates/{id}").resolveTemplates(map).request(CryptoMediaType.APPLICATION_PKIX_CERT).get(X509Certificate.class);
        return certificate;
    }
    
    /**
     * Search the details of the specified certificate from the system using specific filter criteria.
     * @param criteria The content models of the CaCertificateFilterCriteria java model object can be used as query parameters.
     * <pre>
     *              id        ID of the certificate whose values can be root, saml, privacy, aik, endorsement, ek or tls. 
     *                        The CaCertificates search using the certificateID is not supported.
     *
     *             domain    Domain name of the certificate. The domain name values allowed for the search criteria
     *                       are "ek" and "endorsement".
     * </pre>
     * @since Mt.Wilson 2.0
     * @mtwRequiresPermissions None
     * @mtwContentTypeReturned application/x-pem-file
     * @mtwMethodType GET
     * @mtwSampleRestCall
     * <div style="word-wrap: break-word; width: 1024px"><pre>
     * https://server.com:8443/mtwilson/v2/ca-certificates?domain=ek
     * Output:
     *  -----BEGIN CERTIFICATE-----
     * MIIC0zCCAbugAwIBAgIJAP8y0d2XNaa0MA0GCSqGSIb3DQEBCwUAMCkxETAPBgNVBAsTCG10d2ls
     * c29uMRQwEgYDVQQDEwttdHdpbHNvbi1jYTAeFw0xNDA0MjMwNDI0NTdaFw0xNTA0MjMwNDI0NTda
     * MCkxETAPBgNVBAsTCG10d2lsc29uMRQwEgYDVQQDEwttdHdpbHNvbi1jYTCCASIwDQYJKoZIhvcN
     * AQEBBQADggEPADCCAQoCggEBAL6r6DnRdQiuH8uHP/BboABxfwquWwzyX5OY5cjMxfR8RR4XhOi/
     * govUzcFzOotwv6YUM49QVK0c3C4Q5dVuE3EX8PaU7KzCik6DcuMzFdHe4hQzoINIvjDKmW1A3lwp
     * HKEnMTuYkbAnJToEg0G2ZhBX6Ye/kZvLaDpvBF84EJBDjxXKFksLWONyakRXOSLkfIshEvQF6kfz
     * JxCPwxDHAU94svm2Wcl7GLKScr/MUiZxJSIX7GWZSt2LLLq6hQvXXw3XeQCdExmwOipYtAj7JI4u
     * 7lO+bmpQX/UtIGePJCYAtogQ6KbZ+0EnJursdZH2sfJNPuPQ37JOsGf8G6Z+nyUCAwEAATANBgkq
     * hkiG9w0BAQsFAAOCAQEAZbzmOBilsCwCRMakJT//U6kAZLo0DFhBU5ITPz+wGXcO5FcAOMZL3qou
     * YbXL9H7KRMXHa6VcNOOkgoUjrjbOiZtzSWmyVZdjpyeT/9Lct7lLYY+MXMei9SMaiywtLCzAkHf4
     * Ewpl8zaMSjs9baE/18/1SAneyXz6jwrZBua5GJWTDwiZidk3l9MfgRpStYaKXpiian0MTrvp0Lcc
     * 2wzn8esuaBfEx0GGeJQyPDRV3fbpDON9sZRMLjS6pX99XeAdh+qJdjaW9CYsfi40k1vlZRK/Pt2H
     * gkVhnRnidYrMN5Qu4VqEQkd4Gz0jPJW+EfnbM+W/PvlWgDIZvhq7UfpjMA==
     * -----END CERTIFICATE-----
     *  -----BEGIN CERTIFICATE-----
     * MIIC0zCCAbugAwIBAgIJAP8y0d2XNaa0MA0GCSqGSIb3DQEBCwUAMCkxETAPBgNVBAsTCG10d2ls
     * c29uMRQwEgYDVQQDEwttdHdpbHNvbi1jYTAeFw0xNDA0MjMwNDI0NTdaFw0xNTA0MjMwNDI0NTda
     * MCkxETAPBgNVBAsTCG10d2lsc29uMRQwEgYDVQQDEwttdHdpbHNvbi1jYTCCASIwDQYJKoZIhvcN
     * AQEBBQADggEPADCCAQoCggEBAL6r6DnRdQiuH8uHP/BboABxfwquWwzyX5OY5cjMxfR8RR4XhOi/
     * govUzcFzOotwv6YUM49QVK0c3C4Q5dVuE3EX8PaU7KzCik6DcuMzFdHe4hQzoINIvjDKmW1A3lwp
     * HKEnMTuYkbAnJToEg0G2ZhBX6Ye/kZvLaDpvBF84EJBDjxXKFksLWONyakRXOSLkfIshEvQF6kfz
     * JxCPwxDHAU94svm2Wcl7GLKScr/MUiZxJSIX7GWZSt2LLLq6hQvXXw3XeQCdExmwOipYtAj7JI4u
     * 7lO+bmpQX/UtIGePJCYAtogQ6KbZ+0EnJursdZH2sfJNPuPQ37JOsGf8G6Z+nyUCAwEAATANBgkq
     * hkiG9w0BAQsFAAOCAQEAZbzmOBilsCwCRMakJT//U6kAZLo0DFhBU5ITPz+wGXcO5FcAOMZL3qou
     * YbXL9H7KRMXHa6VcNOOkgoUjrjbOiZtzSWmyVZdjpyeT/9Lct7lLYY+MXMei9SMaiywtLCzAkHf4
     * Ewpl8zaMSjs9baE/18/1SAneyXz6jwrZBua5GJWTDwiZidk3l9MfgRpStYaKXpiian0MTrvp0Lcc
     * 2wzn8esuaBfEx0GGeJQyPDRV3fbpDON9sZRMLjS6pX99XeAdh+qJdjaW9CYsfi40k1vlZRK/Pt2H
     * gkVhnRnidYrMN5Qu4VqEQkd4Gz0jPJW+EfnbM+W/PvlWgDIZvhq7UfpjMA==
     * -----END CERTIFICATE-----
     * </pre></div>
     * @return X509Certificate in base 64 encoded format of the requested ID type.
     * @mtwSampleApiCall
     * <div style="word-wrap: break-word; width: 1024px"><pre>
     * // // Create the Ca certificate filter criteria model and set domain
     * CaCertificates client = new CaCertificates(properties);
     * CaCertificateFilterCriteria criteria = new CaCertificatesFilterCriteria();
     * criteria.domain = "ek";
     * 
     * // Create the client and call the search API
     * CaCertificatesCollection EkCertificate = client.searchCaCertificatesPem(criteria);
     * </pre></div>
     */   
    public String searchCaCertificatesPem(CaCertificateFilterCriteria criteria) {
        if(criteria.domain == null) {
            criteria.domain = "ek";
        }
        String certificatesPem = getTargetPathWithQueryParams("ca-certificates", criteria).request(CryptoMediaType.APPLICATION_X_PEM_FILE).get(String.class);
        return certificatesPem;
    }
    
}
