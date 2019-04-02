/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.client.jaxrs;

import com.intel.mtwilson.jaxrs2.client.MtWilsonClient;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.tls.policy.TlsConnection;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import com.intel.mtwilson.core.common.tpm.model.IdentityProofRequest;
import com.intel.mtwilson.privacyca.v2.model.*;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Properties;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Shared privacyca libraries	
 * @author ssbangal
 */
public class PrivacyCA extends MtWilsonClient {
    
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
     * RegisterUsers client = new RegisterUsers(properties);
     * </pre>
     * @throws Exception 
     */
    public PrivacyCA(Properties properties) throws Exception {
        super(properties);
    }
    
    public PrivacyCA(Properties properties, TlsConnection tlsConnection) throws Exception {
        super(properties, tlsConnection);
    }
    
    
    /**
     * <pre>
     * The Endorsement Key Modulus is the public portion of an RSA Keypair that is issued at TPM manufacturing time.
     * The Private portion is to never be revealed by any means, and the TPM has software and hardware (physical) protections
     * against this. This function is useful for TPM's that do not come preinstalled with an Endorsement Credential 
     * (synonymous with Endorsement Certificate) from a Trusted Certificate Authority.The Endorsement Key Modulus can be 
     * sent to a Certificate Authority to receive an Endorsement Certificate.
     * An EK certificate is used to bind an identity or specific security attributes to a TPM. 
     * The primary use of an EK certificate is to authenticate device identity  when an AIK is issued. 
     * </pre>
     * @param ekModulus Endorsement Key Modulus (public key EKpub) blob
     * @return X509Certificate 
     * @since ISecL 1.0
     * @mtwRequiresPermissions tpms:endorse
     * @mtwContentTypeReturned application/x-pem-file
     * @mtwMethodType POST
     * @mtwSampleRestCall 
     * https://server.com:8443/mtwilson/v2/privacyca/tpm-endorsement
     * <pre>
     * Input:
     * {
     *      "ek_modulus":[14, 54, 74, 34]
     * }
     * output:
     * {
     *       -----BEGIN CERTIFICATE-----
     *       MIIBtzCBoKADAgECAgYBY5CUR1YwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAxMPbXR3aWxzb24t
     *       cGNhLWVrMB4XDTE4MDUyNDA1MTcwNloXDTI4MDUyMzA1MTcwNlowADAfMA0GCSqGSIb3DQEBAQUA
     *       Aw4AMAsCBA42SiICAwEAAaMjMCEwHwYDVR0RAQH/BBUwE4ERVFBNIEVLIENyZWRlbnRpYWwwDQYJ
     *       KoZIhvcNAQELBQADggEBACehrGscBMPDzpFnKRAdAwHuk4RneRj5pd2KQN3jM9Ayr33Fd8g/ads0
     *       PFRVdC3YjNR9mYmaQZOM7MDyNMbQdTcHVOT7vN1POlWjlmlpwJr58cAJSsObaq+aGK23DnvE8rmy
     *       WfPYC3Iv2WZdWM4imXKdUIbLSUdHmjVySH0jNsO4OCT76hwCtfbLMqhbihOa89lVFavJGH+z4o+5
     *       1xLCIovQdZlpdPKfB43C27pPxHwYav8fGfaPVdfly9pykXeE/OtC1Ikszgipu7hQZORYkoMx7uUE
     *       9kESv4bni5IxbQQJF9I6CCDEBz74sC7uJlrEbrez2BE0VIUOKbkXsEfcoII=
     *       -----END CERTIFICATE-----
     * }
     * </pre>
     * @mtwSampleApiCall  
     * <pre>
     * PrivacyCa client = new PrivacyCa(properties);
     * byte[] ekModulus = [ekModulus blob];
     * X509Certificate ec = client.endorseTpm(ekModulus);
     * </pre>
     */
    public X509Certificate endorseTpm(byte[] ekModulus) {
        log.debug("target: {}", getTarget().getUri().toString());
        X509Certificate ec = getTarget()
                .path("/privacyca/tpm-endorsement")
                .request()
                .accept(CryptoMediaType.APPLICATION_X_PEM_FILE)
                .post(Entity.entity(ekModulus, MediaType.APPLICATION_OCTET_STREAM), X509Certificate.class);
        return ec;
    }
    /**Is used to request attestation service for challenge to prove identity of host.
     * <pre>
     * An identity request is generally created by running the TSS function Tspi_TPM_CollateIdentityRequest.
     * The request contains two parts: a symmetrically encrypted identity proof (TPM_IDENTITY_PROOF); and an asymmetrically encrypted portion 
     * containing the key used to encrypt the symmetric portion. This method decodes and decrypts 
     * the identity request and returns an identity proof. 
     * </pre>
     * @param challengeRequest The IdentityChallengeRequest java model object represents the content of the request body.
     * <pre>  
     *        identityRequest (required)      IdentityRequest model contains following attributes:
     *          
     *                                          tpmVersion              TPM version.
     * 
     *                                          identityRequestBlob     The Identity Request, as returned from
     *                                                                  CollateIdentityRequest, in raw byte form.
     * 
     *                                          aikModulus              The AIK modulus.
     *                                                  
     *                                          aikBlob                 The AIK in the form of a TPM_KEY.
     *                                                  
     *                                          aikName                 The AIK label/name represented as a byte buffer.
     * 
     *         endorsementCertificate (required)    Endorsement Certificate.
     *</pre>
     *@return The serialized IdentityProofRequest java model object that was created:
     * <pre>
     *              asymBlob
     *              symBlob
     *              ekBlob
     *              secret 
     *              credential
     * </pre>
     * @since ISecL 1.0
     * @mtwRequiresPermissions None
     * @mtwContentTypeReturned JSON/XML/YAML
     * @mtwMethodType POST
     * @mtwSampleRestCall      
     * <pre>
     * https://server.com:8443/mtwilson/v2/privacyca/identity-challenge-request
     * Input:
     *  {
     *      "identity_request":{
     *             "tpm_version":"2.0",
     *             "identity_request_blob":[identityRequest blob]
     *             "aik_modulus":[aikModulus blob],
     *             "aik_blob":[aik blob],
     *             "aik_name":[aikName blob]
     *    },
     *      "endorsement_certificate": [blob of endorsement certificate]
     *  }
     * output: 
     * {
     *              "secret"     :        "AAGB9Xr+ti6dsDSph9FqM1tOM8LLWLLhUhb89R6agQ/hA+eQDF2FpcfOM/98J95ywwYpx
     *                                     zYS8Nx6c7ud5e6SVVgLldcc3/m9xfsCC7tEmfQRyc+pydbgnCHQ9E/TQoyV/VgiE5ssV+
     *                                     lGX171+lN+2RSO0HC8er+jN52bh31M4S09sv6+Qk2Fm2efDsF2NbFI4eyLcmtFEwKfDyA
     *                                     iZ3zeXqPNQWpUzVZzR3zfxpd6u6ZonYmfOn/fLDPIHwTFv8cYHSIRailTQXP+VmQuyR7Y
     *                                     OI8oe/NC/cr7DIYTJD7GLFNDXk+sybf9j9Ttng4RRyb0WXgIcfIWW1oZD+i4wqu9OdV1",
     *              "credential" :        "NAAAIBVuOfmXFbgcbBA2fLtnl38KQ7fIRGwUSf5kQ+UwIAw8ElXsYfoBoUB11BWKkc4uo
     *                                     9WRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
     *                                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
     *              "sym_blob"   :        "AAAAQAAAAAYAAQAAAAAAAMlZgTkKMlujW0vDUrhcE8Ixut12y5yXXP7nyx8wSUSHIaNz4
     *                                     19fpyAiQdsCG3PMJGvsNtiInB1zjGqQOtt77zM=",
     *              "ek_blob"    :        "Tb3zQv6oW8/dUg45qofJFsIZV1XHTADZgeVjH7BI/ph+6ERJTlxBjK7zkxHJh54QlCi5h
     *                                     0f1rMkYqtAyCmmyyUdewP4xFaVmjm8JcWaAzeOfb3vhamWr9xGecfJ34D58cy2Att7VAz
     *                                     XoWe2GthAblM+Rjsy9wiXfyOe9IjfC5jngjPHfwyi8IvV+FZHTG8wq7R8lcAdurMmOzMZ
     *                                     JT+vkzBq1TEGLurE3h4Rf84X3H/um4sQ2mqo+r5ZIsm+6lhb6PjU4S9Cp3j4RZ5nU/uVv
     *                                     gTWzviNUPYBbd3AypQo9Kv5ij8UqHk2P1DzWjCBvwCqHTzRsuf9b9FeT+f4aWgLNQ=="
     * }
     * </pre>
     * @mtwSampleApiCall   
     * <pre>
     * //Create IdentityRequest model object and set tpm version,aikBlob,AikModulus,AikName and IdentityRequest
     * IdentityRequest identityRequest = new IdentityRequest() ;
     * identityRequest.setTpmVersion("2.0");
     * identityRequest.setAikBlob(aikBlob);
     * identityRequest.setAikModulus(aikModulusBlob);
     * identityRequest.setAikName(aikNameBlob);
     * identityRequest.setIdentityRequestBlob(identityRequestBlob);
     * 
     * //Create IdentityChallengeRequest model object and set identityRequest  and endorsementCertificate
     * IdentityChallengeRequest challengeRequest = new IdentityChallengeRequest();
     * challengeRequest.setIdentityRequest(identityRequest);
     * challengeRequest.setEndorsementCertificate(endorsementCertificate);
     * 
     * //Create client and call identityChallengeRequest API
     * PrivacyCA client = new PrivacyCA(properties);
     * IdentityProofRequest proofRequest = client.identityChallengeRequest(challengeRequest);
     * </pre>
     */
     
    public IdentityProofRequest identityChallengeRequest(IdentityChallengeRequest challengeRequest) {
        log.debug("target: {}", getTarget().getUri().toString());
        IdentityProofRequest challenge = getTarget()
                .path("/privacyca/identity-challenge-request")
                .request()
                .accept(MediaType.APPLICATION_JSON)
                .post(Entity.json(challengeRequest), IdentityProofRequest.class);
        return challenge;
    }

    
    /**
     * Find the existing challenge and idproof.The challenge and idproof is used in identity request submit response
     * if the client successfully answers the challenge using the response to challenge.
     *@param challengeResponse The serialized IdentityChallengeResponse java model object represents the content of the request body.
     *<pre>
     *          identityRequest (required)      IdentityRequest model contains following attributes:
     *          
     *                                          tpmVersion              TPM version.
     * 
     *                                          identityRequestBlob     The Identity Request, as returned from
     *                                                                  CollateIdentityRequest, in raw byte form.
     * 
     *                                          aikModulus              The AIK modulus.
     *                                                  
     *                                          aikBlob                 The AIK in the form of a TPM_KEY.
     *                                                  
     *                                          aikName                 The AIK label/name represented as a byte buffer.
     * 
     * 
     *          responseToChallenge (required)  response to challenge blob
     *</pre>
     *@return The serialized IdentityProofRequest java model object that was created:
     * <pre>
     *              asymBlob
     *              symBlob
     *              ekBlob
     *              secret 
     *              credential
     * </pre>
     * @since ISecL 1.0
     * @mtwRequiresPermissions None
     * @mtwContentTypeReturned JSON/XML/YAML
     * @mtwMethodType POST
     * @mtwSampleRestCall      
     * <pre>
     * https://server.com:8443/mtwilson/v2/privacyca/identity-challenge-request
     * input:
     *{
     *      "identity_request":{
     *             "tpm_version":"2.0",
     *             "identity_request_blob":[identityRequest blob],
     *              "aik_modulus":[aikModulus blob],
     *              "aik_blob":[aik blob],
     *              "aik_name":[aikName blob]
     *    },
     *      "response_to_challenge": [responseToChallenge blob ]
     * }
     * output: 
     * {
     *           "secret"        :      "AAGB9Xr+ti6dsDSph9FqM1tOM8LLWLLhUhb89R6agQ/hA+eQDF2FpcfOM/98J95ywwYpxzYS8N
     *                                   x6c7ud5e6SVVgLldcc3/m9xfsCC7tEmfQRyc+pydbgnCHQ9E/TQoyV/VgiE5ssV+lGX171+lN+
     *                                   2RSO0HC8er+jN52bh31M4S09sv6+Qk2Fm2efDsF2NbFI4eyLcmtFEwKfDyAiZ3zeXqPNQWpUzV
     *                                   ZzR3zfxpd6u6ZonYmfOn/fLDPIHwTFv8cYHSIRailTQXP+VmQuyR7YOI8oe/NC/cr7DIYTJD7G
     *                                   LFNDXk+sybf9j9Ttng4RRyb0WXgIcfIWW1oZD+i4wqu9OdV1",
     *           "credential"    :      "NAAAIBVuOfmXFbgcbBA2fLtnl38KQ7fIRGwUSf5kQ+UwIAw8ElXsYfoBoUB11BWKkc4uo9WRAA
     *                                   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
     *                                   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
     *           "sym_blob"      :      "AAAAQAAAAAYAAQAAAAAAAMlZgTkKMlujW0vDUrhcE8Ixut12y5yXXP7nyx8wSUSHIaNz419fpy
     *                                   AiQdsCG3PMJGvsNtiInB1zjGqQOtt77zM=",
     *           "ek_blob"       :      "Tb3zQv6oW8/dUg45qofJFsIZV1XHTADZgeVjH7BI/ph+6ERJTlxBjK7zkxHJh54QlCi5h0f1rM
     *                                   kYqtAyCmmyyUdewP4xFaVmjm8JcWaAzeOfb3vhamWr9xGecfJ34D58cy2Att7VAzXoWe2GthAb
     *                                   lM+Rjsy9wiXfyOe9IjfC5jngjPHfwyi8IvV+FZHTG8wq7R8lcAQdurMmOzMZJT+vkzBq1TEGLu
     *                                   rE3h4Rf84X3H/um4sQ2mqo+r5ZIsm+6lhb6PjU4S9Cp3j4RZ5nU/uVvgTWzviNUPYBbd3AypQo
     *                                   9Kv5ij8UqHk2P1DzWjCBvwCqHTzRsuf9b9FeT+f4aWgLNQ=="
     * }
     * </pre>
     * @mtwSampleApiCall   
     * <pre>
     *  //Create IdentityRequest model object and set tpm version,aikBlob,AikModulus,AikName and IdentityRequest
     * IdentityRequest identityRequest = new IdentityRequest() ;
     * identityRequest.setTpmVersion("2.0");
     * identityRequest.setAikBlob(aikBlob);
     * identityRequest.setAikModulus(aikModulusBlob);
     * identityRequest.setAikName(aikNameBlob);
     * identityRequest.setIdentityRequestBlob(identityRequestBlob);
     * 
     * //Create IdentityChallengeResponse model object and set identityRequest  and responseToChallenge
     * IdentityChallengeResponse challengeResponse = new IdentityChallengeResponse();
     * challengeRequest.setIdentityRequest(identityRequest);
     * challengeRequest.setResponseToChallenge(responseToChallenge);
     * 
     * //Create client and call identityChallengeResponse API
     * PrivacyCA client = new PrivacyCA(properties);
     * IdentityProofRequest proofRequest =  client.identityChallengeResponse(challengeRequest);
     * </pre>
     */
    public IdentityProofRequest identityChallengeResponse(IdentityChallengeResponse challengeResponse) {
        log.debug("target: {}", getTarget().getUri().toString());
        IdentityProofRequest identity = getTarget()
                .path("/privacyca/identity-challenge-response")
                .request()
                .accept(MediaType.APPLICATION_JSON)
                .post(Entity.json(challengeResponse), IdentityProofRequest.class);
        return identity;
    }


}
