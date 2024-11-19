
package com.jadorno.guacamole;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.net.auth.simple.SimpleActivityRecordSet;
import org.apache.guacamole.net.auth.simple.SimpleDirectory;
import org.apache.guacamole.net.auth.simple.SimpleObjectPermissionSet;
import org.apache.guacamole.net.auth.simple.SimpleUser;
import org.apache.guacamole.net.GuacamoleSocket;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.InetGuacamoleSocket;
import org.apache.guacamole.net.SimpleGuacamoleTunnel;
import org.apache.guacamole.net.auth.AbstractAuthenticatedUser;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.GuacamoleProxyConfiguration;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.net.auth.permission.ObjectPermissionSet;
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.mindrot.jbcrypt.BCrypt;
import org.apache.guacamole.net.auth.AbstractUserContext;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.apache.guacamole.net.SSLGuacamoleSocket;
import org.apache.guacamole.net.auth.AbstractConnection;
import org.apache.guacamole.net.auth.ActivityRecordSet;
import org.apache.guacamole.net.auth.ConnectionRecord;
import org.apache.guacamole.protocol.ConfiguredGuacamoleSocket;
import org.apache.guacamole.token.TokenFilter;
import java.util.Date;

public class MyAuthenticationProvider extends AbstractAuthenticationProvider {

    @Override
    public String getIdentifier() {
        return "guacamole-dataprovider-yml";
    }

    @Override
    public AuthenticatedUser authenticateUser(final Credentials credentials) throws GuacamoleException {

        String username = credentials.getUsername(); 
        ParseUser config = getUserData(username);

        if(config != null){
            if(config.pasword == null || BCrypt.checkpw(credentials.getPassword(), config.pasword)){
                return new MyAuthenticatedUser(credentials, this);
            }
        }
        return null;

    }

    @Override
    public UserContext getUserContext(AuthenticatedUser authenticatedUser) throws GuacamoleException {

        String username = authenticatedUser.getCredentials().getUsername(); 
        ParseUser config = getUserData(username);

        if(config == null)
            return null;
        else
            return new MyUserContext(this, config);
    }

    private ParseUser getUserData(String username){
        try {

            Environment e = LocalEnvironment.getInstance() ;

            Constructor constructor = new Constructor(ParseConfig.class, new LoaderOptions());
            Yaml yaml = new Yaml(constructor);
            File file = new File(e.getGuacamoleHome(), "users.yml");
            InputStream inputStream = new FileInputStream(file);
            ParseConfig instance = yaml.load(inputStream);

            for(ParseUser user : instance.users){
                if(user.username.equals(username))
                    return user;
            }
            return null;
            
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private class MyUserContext extends AbstractUserContext {

        private final AuthenticationProvider authProvider;
        private final String username;
        private final Directory<Connection> connectionDirectory;
    
        public MyUserContext(AuthenticationProvider authProvider, ParseUser user) throws GuacamoleException {
            
            Map<String, Connection> connections = new ConcurrentHashMap<String, Connection>(user.connections.size());

            for(ParseConnection config : user.connections){

                GuacamoleConfiguration guacamoleConfiguration = new GuacamoleConfiguration();
                guacamoleConfiguration.setProtocol(config.protocol);
                guacamoleConfiguration.setParameters(config.parameters);

                GuacamoleProxyConfiguration proxyConfig = LocalEnvironment.getInstance().getDefaultGuacamoleProxyConfiguration();
                if(config.attributes != null && config.attributes.containsKey("guacd-hostname"))
                    proxyConfig = new GuacamoleProxyConfiguration(config.attributes.get("guacd-hostname"), proxyConfig.getPort(), proxyConfig.getEncryptionMethod());

                Connection connection = new MySimpleConnection(config.name, config.name, proxyConfig, guacamoleConfiguration, false);
                connection.setParentIdentifier(DEFAULT_ROOT_CONNECTION_GROUP);
                connections.put(config.name, connection);

            }
            this.username = user.username;
            this.authProvider = authProvider;
            this.connectionDirectory = new SimpleDirectory<Connection>(connections);
        }

        @Override
        public User self() {
            return new SimpleUser(username) {
    
                @Override
                public ObjectPermissionSet getConnectionGroupPermissions() throws GuacamoleException {
                    return new SimpleObjectPermissionSet(getConnectionDirectory().getIdentifiers());
                }
    
                @Override
                public ObjectPermissionSet getConnectionPermissions() throws GuacamoleException {
                    return new SimpleObjectPermissionSet(getConnectionGroupDirectory().getIdentifiers());
                }
    
            };
        }
    
        @Override
        public Object getResource() throws GuacamoleException {
            return null;
        }
    
        @Override
        public AuthenticationProvider getAuthenticationProvider() {
            return authProvider;
        }
    
        @Override
        public Directory<Connection> getConnectionDirectory() throws GuacamoleException {
            return connectionDirectory;
        }
    }

    public class MyAuthenticatedUser extends AbstractAuthenticatedUser {
        private final Credentials credentials;
        private final AuthenticationProvider authProvider;

        public MyAuthenticatedUser(Credentials credentials, AuthenticationProvider authProvider) {
            this.credentials = credentials;
            this.authProvider = authProvider;
            String username = credentials.getUsername();
            if (username != null && !username.isEmpty())
                setIdentifier(username);
            else
                setIdentifier(UUID.randomUUID().toString());
        }
    
        @Override
        public AuthenticationProvider getAuthenticationProvider() {
            return authProvider;
        }
    
        @Override
        public Credentials getCredentials() {
            return credentials;
        }
    
        @Override
        public Set<String> getEffectiveUserGroups() {
            return Collections.<String>emptySet();
        }
    }

    private class MySimpleConnection extends AbstractConnection {

        private GuacamoleConfiguration fullConfig;
        private GuacamoleProxyConfiguration proxyConfig;
        private final boolean interpretTokens;
        private final ThreadLocal<Map<String, String>> currentTokens = new ThreadLocal<Map<String, String>>() {
            @Override
            protected Map<String, String> initialValue() {
                return Collections.emptyMap();
            }
        };

        public MySimpleConnection(String name, String identifier, GuacamoleProxyConfiguration proxyConfig, GuacamoleConfiguration config, boolean interpretTokens) {

            super.setName(name);
            super.setIdentifier(identifier);
            super.setConfiguration(config);

            this.proxyConfig = proxyConfig;
            this.fullConfig = config;
            this.interpretTokens = interpretTokens;

        }

        protected GuacamoleConfiguration getFullConfiguration() {
            return fullConfig;
        }

        @Override
        public void setConfiguration(GuacamoleConfiguration config) {
            super.setConfiguration(config);
            this.fullConfig = config;
        }

        @Override
        public int getActiveConnections() {
            return 0;
        }

        @Override
        public Map<String, String> getAttributes() {
            return Collections.<String, String>emptyMap();
        }

        @Override
        public void setAttributes(Map<String, String> attributes) {
            // Do nothing - there are no attributes
        }

        @Override
        @Deprecated
        public GuacamoleTunnel connect(GuacamoleClientInformation info) throws GuacamoleException {

            // Get guacd connection parameters
            String hostname = proxyConfig.getHostname();
            int port = proxyConfig.getPort();

            // Apply tokens to config parameters
            GuacamoleConfiguration filteredConfig = new GuacamoleConfiguration(getFullConfiguration());
            new TokenFilter(currentTokens.get()).filterValues(filteredConfig.getParameters());

            GuacamoleSocket socket;

            // Determine socket type based on required encryption method
            switch (proxyConfig.getEncryptionMethod()) {

                // If guacd requires SSL, use it
                case SSL:
                    socket = new ConfiguredGuacamoleSocket(
                        new SSLGuacamoleSocket(hostname, port),
                        filteredConfig, info
                    );
                    break;

                // Connect directly via TCP if encryption is not enabled
                case NONE:
                    socket = new ConfiguredGuacamoleSocket(
                        new InetGuacamoleSocket(hostname, port),
                        filteredConfig, info
                    );
                    break;

                // Abort if encryption method is unknown
                default:
                    throw new GuacamoleServerException("Unimplemented encryption method.");
            }
            return new SimpleGuacamoleTunnel(socket);
        }

        @Override
        public GuacamoleTunnel connect(GuacamoleClientInformation info, Map<String, String> tokens) throws GuacamoleException {

            // Make received tokens available within the legacy connect() strictly
            // in context of the current connect() call
            try {

                // Automatically filter configurations only if explicitly
                // configured to do so
                if (interpretTokens)
                    currentTokens.set(tokens);

                return connect(info);
            }
            finally {
                currentTokens.remove();
            }
        }

        @Override
        public Date getLastActive() {
            return null;
        }
        
        @Override
        public ActivityRecordSet<ConnectionRecord> getConnectionHistory()
                throws GuacamoleException {
            return new SimpleActivityRecordSet<>();
        }
    }


}

