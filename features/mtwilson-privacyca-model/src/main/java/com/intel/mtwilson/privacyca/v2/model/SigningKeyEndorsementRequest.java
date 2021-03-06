/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.privacyca.v2.model;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author ssbangal
 */
@JacksonXmlRootElement(localName="signing_key_endorsement_request")
public class SigningKeyEndorsementRequest{
    
    Logger log = LoggerFactory.getLogger(getClass().getName());
    
    private byte[] publicKeyModulus;
    private byte[] tpmCertifyKey;
    private byte[] tpmCertifyKeySignature;
    private byte[] aikDerCertificate;
    private byte[] nameDigest;
    private String tpmVersion = null;
    private String operatingSystem = null;
    
    public byte[] getNameDigest() {
        return nameDigest;
    }
    public void setNameDigest(byte[] digest) {
        this.nameDigest = digest;
    }

    public byte[] getPublicKeyModulus() {
        return publicKeyModulus;
    }

    public void setPublicKeyModulus(byte[] publicKeyModulus) {
        this.publicKeyModulus = publicKeyModulus;
    }

    public byte[] getTpmCertifyKey() {
        return tpmCertifyKey;
    }

    public void setTpmCertifyKey(byte[] tpmCertifyKey) {
        this.tpmCertifyKey = tpmCertifyKey;
    }    

    public byte[] getTpmCertifyKeySignature() {
        return tpmCertifyKeySignature;
    }

    public void setTpmCertifyKeySignature(byte[] tpmCertifyKeySignature) {
        this.tpmCertifyKeySignature = tpmCertifyKeySignature;
    }

    public byte[] getAikDerCertificate() {
        return aikDerCertificate;
    }

    public void setAikDerCertificate(byte[] aikDerCertificate) {
        this.aikDerCertificate = aikDerCertificate;
    }
    
     public String getOperatingSystem(){
        return operatingSystem;
    }

    public void setOperatingSystem(String os){
        this.operatingSystem=os;
    }
    
    public String getTpmVersion(){
        return tpmVersion;
    }

    public void setTpmVersion(String version){
        this.tpmVersion=version;
    }

}
