package org.keycloak.services.x509;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * The factory and the corresponding providers extract a client certificate
 * from a Traefik reverse proxy (TLS termination).
 *
 * @author <a href="mailto:rtribotte@users.noreply.github.com">Romain</a>
 * @version $Revision: 1 $
 * @since 2/15/2023
 */

public class TraefikProxySslClientCertificateLookupFactory implements X509ClientCertificateLookupFactory {

    private static final Logger logger = Logger.getLogger(TraefikProxySslClientCertificateLookupFactory.class);

    private static final String PROVIDER = "traefik";
    public static final String TRAEFIK_HTTP_HEADER_CLIENT_CERT = "ssl-client-cert";
    public static final String TRAEFIK_ENCODED_HEADER = "encoded-ssl-client-cert";
    private static final String TRAEFIK_DEFAULT_HEADER_CLIENT_CERT = "X-Forwarded-Tls-Client-Cert";
    private static final Boolean TRAEFIK_DEFAULT_ENCODED_HEADER = false;

    private String sslClientCertHttpHeader;
    private Boolean encodedHeader;

    @Override
    public void init(Config.Scope config) {
        if (config != null) {
            sslClientCertHttpHeader = config.get(TRAEFIK_HTTP_HEADER_CLIENT_CERT, TRAEFIK_DEFAULT_HEADER_CLIENT_CERT);
            encodedHeader = config.getBoolean(TRAEFIK_ENCODED_HEADER, TRAEFIK_DEFAULT_ENCODED_HEADER);
            logger.tracev("{0}:   ''{1}''", TRAEFIK_HTTP_HEADER_CLIENT_CERT, sslClientCertHttpHeader);
        }
        else {
            logger.tracev("No configuration for ''{0}'' reverse proxy was found", this.getId());
            sslClientCertHttpHeader = TRAEFIK_DEFAULT_HEADER_CLIENT_CERT;
            encodedHeader = TRAEFIK_DEFAULT_ENCODED_HEADER;
        }
    }

    @Override
    public X509ClientCertificateLookup create(KeycloakSession session) {
        return new TraefikProxySslClientCertificateLookup(sslClientCertHttpHeader, encodedHeader);
    }

    @Override
    public String getId() {
        return PROVIDER;
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {

    }
}
