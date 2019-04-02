/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.privacyca.v2.model;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;

/**
 *
 * @author jbuhacoff
 */
@JacksonXmlRootElement(localName="endorse_tpm_request")
public class EndorseTpmRequest {
    private byte[] ekModulus;

    public void setEkModulus(byte[] ekModulus) {
        this.ekModulus = ekModulus;
    }

    public byte[] getEkModulus() {
        return ekModulus;
    }    
}
