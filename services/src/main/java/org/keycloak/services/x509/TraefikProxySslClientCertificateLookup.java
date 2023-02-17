/*
 * Copyright 2017 Analytical Graphics, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.keycloak.services.x509;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.common.util.PemException;
import org.keycloak.common.util.PemUtils;
import org.keycloak.http.HttpRequest;

/**
 *
 * @author <a href="mailto:rtribotte@users.noreply.github.com">Romain</a>
 * @version $Revision: 1 $
 * @since 2/15/2023
 */

public class TraefikProxySslClientCertificateLookup implements X509ClientCertificateLookup {

    protected static final Logger logger = Logger.getLogger(TraefikProxySslClientCertificateLookup.class);

    protected final String sslClientCertHttpHeader;
    protected final boolean encodedHeader;

    public TraefikProxySslClientCertificateLookup(String sslCientCertHttpHeader, Boolean encodedHeader) {
        if (sslCientCertHttpHeader == null) {
            throw new IllegalArgumentException("sslClientCertHttpHeader");
        }

        if (encodedHeader == null) {
            throw new IllegalArgumentException("encodedHeader");
        }

        this.sslClientCertHttpHeader = sslCientCertHttpHeader;
        this.encodedHeader = encodedHeader;
    }

    @Override
    public void close() {

    }

    @Override
    public X509Certificate[] getCertificateChain(HttpRequest httpRequest) throws GeneralSecurityException {
        List<X509Certificate> chain = new ArrayList<>();

        String headerValue = httpRequest.getHttpHeaders().getRequestHeaders().getFirst(sslClientCertHttpHeader);
        if (headerValue == null || headerValue.length() == 0){
            throw new GeneralSecurityException("Unable to find SSL client certificate httpHeader: \"" + sslClientCertHttpHeader + "\".");
        }

        String[] pemCerts = headerValue.split(",");
        if (pemCerts.length == 0){
            throw new GeneralSecurityException("Unable to find SSL client certificate pem value in \"" + sslClientCertHttpHeader + "\" header.");
        }
        
        for (String pemCert : pemCerts) {
            if (encodedHeader) {
                try {
                    pemCert = java.net.URLDecoder.decode(pemCert, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    logger.error(e.getMessage(), e);
                    throw new GeneralSecurityException("Unable to url-decode SSL client certificate.", e);
                }
            }

            try {
                X509Certificate cert = PemUtils.decodeCertificate(pemCert);
                chain.add(cert);
            }
            catch(PemException e) {
                logger.error(e.getMessage(), e);
                throw new GeneralSecurityException("Unable to decode PEM SSL client certificate.", e);
            }
        }

        return chain.toArray(new X509Certificate[0]);
    }
}
