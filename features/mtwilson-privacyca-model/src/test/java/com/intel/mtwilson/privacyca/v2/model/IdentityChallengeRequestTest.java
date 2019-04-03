/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.privacyca.v2.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.mtwilson.core.common.tpm.model.IdentityRequest;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author jbuhacoff
 */
public class IdentityChallengeRequestTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(IdentityChallengeRequestTest.class);
    
    @Test
    public void testJsonEncode() throws JsonProcessingException {
        // create a bogus request with fake data to test encoding/decoding
        IdentityChallengeRequest identityChallengeRequest = new IdentityChallengeRequest();
        IdentityRequest req = new IdentityRequest();
        byte[] dummyData = new byte[] { 0, 1, 2, 3};
        req.setAikBlob(dummyData);
        req.setAikModulus(dummyData);
        req.setAikName("HIS_Identity_Key".getBytes());
        log.debug("The AIK blob is {}", req.getAikName());
        req.setTpmVersion("2.1TEST");
        req.setIdentityRequestBlob(dummyData);
        identityChallengeRequest.setIdentityRequest(req);
        identityChallengeRequest.setEndorsementCertificate(new byte[] { 4, 4, 4, 4 });
        ObjectMapper mapper = new ObjectMapper(); // note that this will produce camelStyle properties while mtwilson api uses a lowercase_with_underscorse rule ;  so this output is NOT suitable for documentation
        log.debug("json: {}", mapper.writeValueAsString(identityChallengeRequest));
    }
    
    @Test
    public void testJsonDecode() throws Exception {
        String json = "{\"identityRequest\":{\"tpmVersion\":\"2.1TEST\",\"identityRequestBlob\":\"AAECAw==\",\"aikModulus\":\"AAECAw==\",\"aikBlob\":\"AAECAw==\",\"aikName\":\"SElTX0lkZW50aXR5X0tleQ==\"},\"endorsementCertificate\":\"BAQEBA==\"}";
        ObjectMapper mapper = new ObjectMapper();
        IdentityChallengeRequest identityChallengeRequest = mapper.readValue(json, IdentityChallengeRequest.class);
        log.debug("identity request bytes {}", identityChallengeRequest.getIdentityRequest());
        log.debug("endorsement certificate bytes {}", identityChallengeRequest.getEndorsementCertificate());
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, identityChallengeRequest.getIdentityRequest().getAikBlob());
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, identityChallengeRequest.getIdentityRequest().getAikModulus());
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, identityChallengeRequest.getIdentityRequest().getIdentityRequestBlob());
        assertArrayEquals("HIS_Identity_Key".getBytes(), identityChallengeRequest.getIdentityRequest().getAikName());
        assertEquals("2.1TEST", identityChallengeRequest.getIdentityRequest().getTpmVersion());
        assertArrayEquals(new byte[] { 4, 4, 4, 4 }, identityChallengeRequest.getEndorsementCertificate());
    }
}
