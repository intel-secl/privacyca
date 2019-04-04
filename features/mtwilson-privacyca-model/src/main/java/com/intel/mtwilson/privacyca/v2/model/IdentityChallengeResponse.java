/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.privacyca.v2.model;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;
import com.intel.mtwilson.core.common.tpm.model.IdentityRequest;

/**
 *
 * @author jbuhacoff
 */
@JacksonXmlRootElement(localName="identity_challenge_response")
public class IdentityChallengeResponse {
    private IdentityRequest identityRequest;

    private byte[] responseToChallenge;

    public byte[] getResponseToChallenge() {
        return responseToChallenge;
    }

    public void setResponseToChallenge(byte[] responseToChallenge) {
        this.responseToChallenge = responseToChallenge;
    }
    
    public IdentityRequest getIdentityRequest() {
        return identityRequest;
    }

    public void setIdentityRequest(IdentityRequest identityRequest) {
        this.identityRequest = identityRequest;
    }
}
