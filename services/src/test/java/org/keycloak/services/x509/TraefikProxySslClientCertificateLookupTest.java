package org.keycloak.services.x509;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriInfo;

import org.jboss.resteasy.specimpl.MultivaluedTreeMap;
import org.junit.Test;
import org.keycloak.Config.SystemPropertiesScope;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.http.FormPartValue;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.DefaultKeycloakSessionFactory;

public class TraefikProxySslClientCertificateLookupTest {
    @Test
    public void shouldReadClientCertHeader() {
        // Version: 1
        // SerialNumber: 481535886039632329873080491016862977516759989652
        // IssuerDN: DC=org,DC=cheese,O=Cheese,O=Cheese 2,OU=Simple Signing Section,OU=Simple Signing Section 2,CN=Simple Signing CA,CN=Simple Signing CA 2,C=FR,C=US,L=TOULOUSE,L=LYON,ST=Signing State,ST=Signing State 2,E=simple@signing.com,E=simple2@signing.com
        // Start Date: Thu Dec 06 12:10:36 CET 2018
        // Final Date: Sat Sep 25 13:10:36 CEST 2021
        // SubjectDN: C=FR,ST=Some-State,O=Cheese
        // Public Key: RSA Public Key [3e:a0:96:a9:06:51:b2:e7:28:96:1d:d2:a3:fa:a2:61:49:3f:b0:09],[56:66:d1:a4]
        // modulus: b245ff6d4b70168d601760533cd68d71350c69116e14c668ccaf0880b8dc719e2467447da053ba629f1997f22f3da7fbb44dba3c8ed73fb787ae251d8674335fb8a2a037744596baf3068884019cfb13f3445acfddbdf28f74b66bd46f7b77342be48257e12d280c2cc4ca900e1a28f4f7017e8e414477e1b74eee0f93277147068abc0dfbfa711d5e71cc018f71cece9f4ff92fb6eafc6fbade786eefccf0f57cae2da1c23cce556ce52fa722044891db30ccd374518bf286fd54a3be2abd6454674403d8bc14b1a5df1cff1812ae5bf243d31c960eb536f66ae2e6f6161e692ebfb6561c65e7a578d3b4f1f0bde13dff4fc0ae79a933247d26da85af5a04bd
        // public exponent: 10001
        // Signature Algorithm: SHA256WITHRSA
        // Signature: 47b5af8d597234f141de3a41b33931918965ec38
        //            7d9da9d5fa8137bdc45d40223ca843482fa68195
        //            be59c2852ce69548febe7c7f9ce60622dd69a04d
        //            e1640dd91d90ff6b0b2f1b2a771b058321f5eb11
        //            5892088c85fbcb4d34a63251c10edf1740b00506
        //            81f530c05fe667a301579f80fd910420b953abcc
        //            c5b7d755bdd2b322dedf658c580411c549aae5d7
        //            1f290e059795fde102e7debc62578a9f711989b3
        //            9c5d13e5cab545b589e1b7b7ffd2bbcae5a1b816
        //            02dec6d36c29de1c16bdd4cf36cdaf8f20849cd7
        //            280262d59206864a480a8b934ae46691da7a40cf
        //            5aa79448d19857ffd1ba74deb910c07f93b17a11
        //            116f5b2bcc15e1459ddc65dcd76e047f
        String clientCertHeaderValue = ""
        + "MIIEQDCCAygCFFRY0OBk/L5Se0IZRj3CMljawL2UMA0GCSqGSIb3DQEBCwUAMIIB"
        + "hDETMBEGCgmSJomT8ixkARkWA29yZzEWMBQGCgmSJomT8ixkARkWBmNoZWVzZTEP"
        + "MA0GA1UECgwGQ2hlZXNlMREwDwYDVQQKDAhDaGVlc2UgMjEfMB0GA1UECwwWU2lt"
        + "cGxlIFNpZ25pbmcgU2VjdGlvbjEhMB8GA1UECwwYU2ltcGxlIFNpZ25pbmcgU2Vj"
        + "dGlvbiAyMRowGAYDVQQDDBFTaW1wbGUgU2lnbmluZyBDQTEcMBoGA1UEAwwTU2lt"
        + "cGxlIFNpZ25pbmcgQ0EgMjELMAkGA1UEBhMCRlIxCzAJBgNVBAYTAlVTMREwDwYD"
        + "VQQHDAhUT1VMT1VTRTENMAsGA1UEBwwETFlPTjEWMBQGA1UECAwNU2lnbmluZyBT"
        + "dGF0ZTEYMBYGA1UECAwPU2lnbmluZyBTdGF0ZSAyMSEwHwYJKoZIhvcNAQkBFhJz"
        + "aW1wbGVAc2lnbmluZy5jb20xIjAgBgkqhkiG9w0BCQEWE3NpbXBsZTJAc2lnbmlu"
        + "Zy5jb20wHhcNMTgxMjA2MTExMDM2WhcNMjEwOTI1MTExMDM2WjAzMQswCQYDVQQG"
        + "EwJGUjETMBEGA1UECAwKU29tZS1TdGF0ZTEPMA0GA1UECgwGQ2hlZXNlMIIBIjAN"
        + "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAskX/bUtwFo1gF2BTPNaNcTUMaRFu"
        + "FMZozK8IgLjccZ4kZ0R9oFO6Yp8Zl/IvPaf7tE26PI7XP7eHriUdhnQzX7iioDd0"
        + "RZa68waIhAGc+xPzRFrP3b3yj3S2a9Rve3c0K+SCV+EtKAwsxMqQDhoo9PcBfo5B"
        + "RHfht07uD5MncUcGirwN+/pxHV5xzAGPcc7On0/5L7bq/G+63nhu78zw9XyuLaHC"
        + "PM5VbOUvpyIESJHbMMzTdFGL8ob9VKO+Kr1kVGdEA9i8FLGl3xz/GBKuW/JD0xyW"
        + "DrU29mri5vYWHmkuv7ZWHGXnpXjTtPHwveE9/0/ArnmpMyR9JtqFr1oEvQIDAQAB"
        + "MA0GCSqGSIb3DQEBCwUAA4IBAQBHta+NWXI08UHeOkGzOTGRiWXsOH2dqdX6gTe9"
        + "xF1AIjyoQ0gvpoGVvlnChSzmlUj+vnx/nOYGIt1poE3hZA3ZHZD/awsvGyp3GwWD"
        + "IfXrEViSCIyF+8tNNKYyUcEO3xdAsAUGgfUwwF/mZ6MBV5+A/ZEEILlTq8zFt9dV"
        + "vdKzIt7fZYxYBBHFSarl1x8pDgWXlf3hAufevGJXip9xGYmznF0T5cq1RbWJ4be3"
        + "/9K7yuWhuBYC3sbTbCneHBa91M82za+PIISc1ygCYtWSBoZKSAqLk0rkZpHaekDP"
        + "WqeUSNGYV//RunTeuRDAf5OxehERb1srzBXhRZ3cZdzXbgR/";

        CryptoIntegration.init(null);
        DefaultKeycloakSessionFactory sessionFactory = new DefaultKeycloakSessionFactory();
        KeycloakSession defaultSession = sessionFactory.create();

        TraefikProxySslClientCertificateLookupFactory lookupFactory = new TraefikProxySslClientCertificateLookupFactory();
        
        lookupFactory.init(null);
        X509ClientCertificateLookup lookup = lookupFactory.create(defaultSession);

        X509Certificate[] certs;
        try {
            certs = lookup.getCertificateChain(new HttpRequestMock("X-Forwarded-Tls-Client-Cert", clientCertHeaderValue));

            assertTrue(certs[0].toString().contains("SerialNumber: 481535886039632329873080491016862977516759989652"));
        } catch (GeneralSecurityException e) {
            fail();
        }

        try {
            certs = lookup.getCertificateChain(new HttpRequestMock("X-Forwarded-Tls-Client-Cert", clientCertHeaderValue + "," + clientCertHeaderValue));

            assertTrue(certs[0].toString().contains("SerialNumber: 481535886039632329873080491016862977516759989652"));
            assertTrue(certs[1].toString().contains("SerialNumber: 481535886039632329873080491016862977516759989652"));
        } catch (GeneralSecurityException e) {
            fail();
        }

        SystemPropertiesScope scope = new SystemPropertiesScope("");

        System.setProperty(TraefikProxySslClientCertificateLookupFactory.TRAEFIK_ENCODED_HEADER, "true");
        lookupFactory.init(scope);

        lookup = lookupFactory.create(defaultSession);

        String encoded = "";
        try {
            encoded = java.net.URLEncoder.encode(clientCertHeaderValue, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            fail();
        }

        try {
            certs = lookup.getCertificateChain(new HttpRequestMock("X-Forwarded-Tls-Client-Cert", encoded));

            assertTrue(certs[0].toString().contains("SerialNumber: 481535886039632329873080491016862977516759989652"));
        } catch (GeneralSecurityException e) {
            fail();
        }

        try {
            certs = lookup.getCertificateChain(new HttpRequestMock("X-Forwarded-Tls-Client-Cert", encoded + "," + encoded));

            assertTrue(certs[0].toString().contains("SerialNumber: 481535886039632329873080491016862977516759989652"));
            assertTrue(certs[1].toString().contains("SerialNumber: 481535886039632329873080491016862977516759989652"));
        } catch (GeneralSecurityException e) {
            fail();
        }

        System.setProperty(TraefikProxySslClientCertificateLookupFactory.TRAEFIK_HTTP_HEADER_CLIENT_CERT, "foobar");
        lookupFactory.init(scope);

        lookup = lookupFactory.create(defaultSession);

        try {
            certs = lookup.getCertificateChain(new HttpRequestMock("foobar", encoded));

            assertTrue(certs[0].toString().contains("SerialNumber: 481535886039632329873080491016862977516759989652"));
        } catch (GeneralSecurityException e) {
            fail();
        }

    }
}

class HttpRequestMock implements org.keycloak.http.HttpRequest {

    private HttpHeaders headers;

    public HttpRequestMock(String clientCertHeaderKey, String clientCertHeaderValue){
        headers = new HttpHeadersMock(clientCertHeaderKey, clientCertHeaderValue);
    }

    @Override
    public String getHttpMethod() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public MultivaluedMap<String, String> getDecodedFormParameters() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public MultivaluedMap<String, FormPartValue> getMultiPartFormParameters() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public HttpHeaders getHttpHeaders() {
        return headers;
    }

    @Override
    public X509Certificate[] getClientCertificateChain() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public UriInfo getUri() {
        // TODO Auto-generated method stub
        return null;
    }

}

class HttpHeadersMock implements javax.ws.rs.core.HttpHeaders {

    private MultivaluedTreeMap<String, String> headers;

    public HttpHeadersMock(String clientCertHeaderKey, String clientCertHeaderValue){
        headers = new MultivaluedTreeMap<String, String>();
        headers.add(clientCertHeaderKey, clientCertHeaderValue);
    }

    @Override
    public List<String> getRequestHeader(String name) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getHeaderString(String name) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public MultivaluedMap<String, String> getRequestHeaders() {
        return headers;
    }

    @Override
    public List<MediaType> getAcceptableMediaTypes() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<Locale> getAcceptableLanguages() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public MediaType getMediaType() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Locale getLanguage() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Map<String, Cookie> getCookies() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Date getDate() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public int getLength() {
        // TODO Auto-generated method stub
        return 0;
    }
    
}