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
@JacksonXmlRootElement(localName="identity_challenge_request")
public class IdentityChallengeRequest {
    private IdentityRequest identityRequest;
    private byte[] endorsementCertificate;

    public void setEndorsementCertificate(byte[] endorsementCertificate) {
        this.endorsementCertificate = endorsementCertificate;
    }

    public byte[] getEndorsementCertificate() {
        return endorsementCertificate;
    }

    public IdentityRequest getIdentityRequest() {
        return identityRequest;
    }

    public void setIdentityRequest(IdentityRequest proofRequest) {
        this.identityRequest = proofRequest;
    }
}
