
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
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.net.auth.simple.SimpleConnection;
import org.apache.guacamole.net.auth.simple.SimpleDirectory;
import org.apache.guacamole.net.auth.simple.SimpleObjectPermissionSet;
import org.apache.guacamole.net.auth.simple.SimpleUser;
import org.apache.guacamole.net.auth.AbstractAuthenticatedUser;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.net.auth.permission.ObjectPermissionSet;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.mindrot.jbcrypt.BCrypt;
import org.apache.guacamole.net.auth.AbstractUserContext;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

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
    
        public MyUserContext(AuthenticationProvider authProvider, ParseUser user) {
            
            Map<String, Connection> connections = new ConcurrentHashMap<String, Connection>(user.connections.size());

            for(ParseConnection config : user.connections){

                GuacamoleConfiguration guacamoleConfiguration = new GuacamoleConfiguration();
                guacamoleConfiguration.setProtocol(config.protocol);
                guacamoleConfiguration.setParameters(config.parameters);
        
                Connection connection = new SimpleConnection(config.name, config.name, guacamoleConfiguration, false);
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
}

