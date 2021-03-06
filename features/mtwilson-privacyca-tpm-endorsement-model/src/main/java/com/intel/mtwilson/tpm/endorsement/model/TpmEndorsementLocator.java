/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.tpm.endorsement.model;

import com.intel.dcsg.cpg.io.UUID;
import com.intel.mtwilson.repository.Locator;
import javax.ws.rs.PathParam;

/**
 *
 * @author jbuhacoff
 */
public class TpmEndorsementLocator implements Locator<TpmEndorsement> {

    @PathParam("id")
    public UUID id;

    @Override
    public void copyTo(TpmEndorsement item) {
        if( id != null ) {
            item.setId(id);
        }        
    }
    
}
