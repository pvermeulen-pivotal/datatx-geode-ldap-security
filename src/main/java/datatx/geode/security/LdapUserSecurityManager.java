package datatx.geode.security;

import org.apache.commons.lang.StringUtils;
import org.apache.geode.security.AuthenticationFailedException;
import org.apache.geode.security.NotAuthorizedException;
import org.apache.geode.security.ResourcePermission;
import org.apache.geode.security.SecurityManager;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchResult;
import java.security.Principal;
import java.util.*;

public class LdapUserSecurityManager implements SecurityManager {
    private NamingEnumeration<?> authorities;

    private String ldapUrlScheme = "ldap://";
    private String ldapServer = "";
    private String basedn;
    private long ldapRefreshTime = 0;

    public static final String LDAP_SERVER_NAME = "security-ldap-server";
    public static final String LDAP_BASEDN_NAME = "security-ldap-basedn";
    public static final String LDAP_SSL_NAME = "security-ldap-usessl";

    public static final String LDAP_AUTHORITIES_GROUP = "security-ldapAuthoritiesGroup";
    public static final String LDAP_GEMFIRE_AUTHZ_QUERY = "security-ldapGemfireAuthorizationQuery";
    public static final String ENCRYPTION_KEY="ENCRYPTED";
    public static final String LDAP_CREDENTIAL_REFRESH_TIME = "security-credentials-refresh";

    private Map<String, User> userAuthorities = new HashMap<String, User>();
    private String authoritiesGroup;
    private String ldapQuery;

    void setUserAuthorities(Map<String, User> userAuthorities){
        this.userAuthorities = userAuthorities;
    }

    public void init(final Properties securityProperties) throws NotAuthorizedException {
        this.ldapServer = securityProperties.getProperty(LDAP_SERVER_NAME);
        if (this.ldapServer == null || this.ldapServer.length() == 0) {
            throw new AuthenticationFailedException(
                    "LdapUserAuthenticator: LDAP server property [" + LDAP_SERVER_NAME + "] not specified");
        }

        this.basedn = securityProperties.getProperty(LDAP_BASEDN_NAME);
        if (this.basedn == null || this.basedn.length() == 0) {
            throw new AuthenticationFailedException(
                    "LdapUserAuthenticator: LDAP base DN property [" + LDAP_BASEDN_NAME + "] not specified");
        }

        authoritiesGroup = securityProperties.getProperty(LDAP_AUTHORITIES_GROUP);
        if (authoritiesGroup == null) {
            throw new AuthenticationFailedException(
                    "LdapUserAuthenticator: LDAP server property [" + LDAP_AUTHORITIES_GROUP + "] not specified");
        }

        ldapQuery = securityProperties.getProperty(LDAP_GEMFIRE_AUTHZ_QUERY);
        if (ldapQuery == null) {
            throw new AuthenticationFailedException(
                    "LdapUserAuthenticator: LDAP server property [" + LDAP_GEMFIRE_AUTHZ_QUERY + "] not specified");
        }

        String refreshTime = securityProperties.getProperty(LDAP_CREDENTIAL_REFRESH_TIME);
        if (StringUtils.isNotEmpty(refreshTime) && StringUtils.isNumeric(refreshTime)){
            ldapRefreshTime = (Long.parseLong(refreshTime)*60)*1000;
        } else {
            ldapRefreshTime = (30*60)*1000;
        }

        if (ldapQuery == null) {
            throw new AuthenticationFailedException(
                    "LdapUserAuthenticator: LDAP server property [" + LDAP_GEMFIRE_AUTHZ_QUERY + "] not specified");
        }

        String sslStr = securityProperties.getProperty(LDAP_SSL_NAME);
        if (sslStr != null && sslStr.toLowerCase().equals("true")) {
            this.ldapUrlScheme = "ldaps://";
        } else {
            this.ldapUrlScheme = "ldap://";
        }
    }

    public Principal authenticate(final Properties credentials) throws AuthenticationFailedException {
        String userName = credentials.getProperty(UserPasswordAuthInit.USER_NAME);
        if (userName == null) {
            throw new AuthenticationFailedException("LdapUserAuthenticator: user name property [" + UserPasswordAuthInit.USER_NAME + "] not provided");
        }
        String passwd = credentials.getProperty(UserPasswordAuthInit.PASSWORD);
        if (passwd == null) {
            throw new AuthenticationFailedException("LdapUserAuthenticator: password name property [" + UserPasswordAuthInit.PASSWORD + "] not provided");
        }

        Optional<UsernamePrincipal> userNamePrincipalOpt = checkUserNeedsToBeRefreshed(userName);

        if (userNamePrincipalOpt.isPresent()) {
            return userNamePrincipalOpt.get();
        }

        Properties env = new Properties();

        if (passwd.startsWith(ENCRYPTION_KEY)) {
            try {
                passwd = passwd.substring(ENCRYPTION_KEY.length());
                env.put(Context.SECURITY_CREDENTIALS, Encryption.decrypt(passwd));
            } catch (Encryption.PeerAuthException ce) {
                throw new AuthenticationFailedException(ce.getMessage());
            }
        } else {
            env.put(Context.SECURITY_CREDENTIALS, passwd);
        }

        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

        env.put(Context.PROVIDER_URL, this.ldapUrlScheme + this.ldapServer);
        String fullentry = "cn=" + userName + "," + this.basedn;
        env.put(Context.SECURITY_PRINCIPAL, fullentry);

        try {
            DirContext ctx = new InitialDirContext(env); 
            authorities = ctx.search(authoritiesGroup, ldapQuery, new Object[]{userName}, null);
            ctx.close();

            List<ResourcePermission> allOfUsersPermissions = new ArrayList<ResourcePermission>();
            while (authorities.hasMoreElements()) {
                SearchResult nextSearchResult = ((SearchResult) authorities.nextElement());
                List<ResourcePermission> resourcePermissions = readPermission(nextSearchResult.getName());
                allOfUsersPermissions.addAll(resourcePermissions);
            }

            if (null == userAuthorities.get(userName)) {
                User user = User.newBuilder()
                        .withName(userName)
                        .withLastTimeAuthenticatedWithLDAP(System.currentTimeMillis())
                        .withRoles(allOfUsersPermissions)
                        .build();
                userAuthorities.put(userName, user);
            } else {
                userAuthorities.get(userName).setLastTimeAuthenticatedWithLDAP(System.currentTimeMillis());
                userAuthorities.get(userName).setRoles(allOfUsersPermissions);
            }

        } catch (Exception e) {
            throw new AuthenticationFailedException("LdapUserAuthenticator: Failure with provided username, password "
                    + "combination for user name: " + userName + "\n Original exception message was: " + e.getMessage());
        }
        return new UsernamePrincipal(userName);
    }

    Optional<UsernamePrincipal> checkUserNeedsToBeRefreshed(String userName) {
        User currentUser = userAuthorities.get(userName);
        if (currentUser != null) {
            if (((System.currentTimeMillis()+ ldapRefreshTime) -  currentUser.getLastTimeAuthenticatedWithLDAP()) > 0) {
                return Optional.of(new UsernamePrincipal(userName));
            }
        }
        return Optional.empty();
    }

    public boolean authorize(final Object principal, final ResourcePermission context) {
        if (principal == null)
            return false;
        User user = this.userAuthorities.get(principal.toString());
        if (user == null)
            return false; 

        for (ResourcePermission resourcePermission : this.userAuthorities.get(user.name).roles) {
            if (resourcePermission == null)
                continue;

            if (resourcePermission.implies(context)) {
                return true;
            }

        }
        return false;
    }

    protected List<ResourcePermission> readPermission(String authorityString) {
        String ldapRoles = authorityString.split(",")[0].replace("cn=", "");
        String[] ldapRole = ldapRoles.split("_");

        if (isValidLdapRole(ldapRole)) {
            return createResourcePermissions(ldapRole);
        }

        return null;
    }

    private boolean isValidLdapRole(String[] ldapRole) {
        return (ldapRole[0].equalsIgnoreCase("INCENTIVES") || ldapRole[0].equalsIgnoreCase("MEMBER") || ldapRole[0].equalsIgnoreCase("COVERAGES"))
                && ldapRole.length >= 4
                && (ldapRole[1].equalsIgnoreCase("ADMIN") || ldapRole[1].equalsIgnoreCase("FUNCTION"))
                && (ldapRole[2].equalsIgnoreCase("CLUSTER") || ldapRole[2].equalsIgnoreCase("DATA"));
    }

    private List<ResourcePermission> createResourcePermissions(String[] ldapRole) {
        String resource = ldapRole[2].toUpperCase();
        String operations = ldapRole[3].toUpperCase();
        String regionName = "*";
        if (ldapRole.length > 4) {
            regionName = ldapRole[4];
        }

        List<ResourcePermission> resourcePermissions = new ArrayList<ResourcePermission>();
        for (int i = 0; i < operations.length(); i++) {
            switch (operations.charAt(i)) {
                case 'M':
                    resourcePermissions.add(new ResourcePermission(ResourcePermission.Resource.valueOf(resource), ResourcePermission.Operation.MANAGE, regionName));
                    break;
                case 'R':
                    resourcePermissions.add(new ResourcePermission(ResourcePermission.Resource.valueOf(resource), ResourcePermission.Operation.READ, regionName));
                    break;
                case 'W':
                    resourcePermissions.add(new ResourcePermission(ResourcePermission.Resource.valueOf(resource), ResourcePermission.Operation.WRITE, regionName));
                    break;
            }
        }
        return resourcePermissions;
    }

    public static class User {
        String name;
        String password;
        long lastTimeAuthenticatedWithLDAP = 0;

        List<ResourcePermission> roles = new ArrayList<ResourcePermission>();

        private User(Builder builder) {
            name = builder.name;
            password = builder.password;
            roles = builder.roles;
        }

        public void setLastTimeAuthenticatedWithLDAP(long lastTimeAuthenticatedWithLDAP) {
            this.lastTimeAuthenticatedWithLDAP = lastTimeAuthenticatedWithLDAP;
        }

        public void setRoles(List<ResourcePermission> permissions) {
            this.roles = permissions;
        }

        public static Builder newBuilder() {
            return new Builder();
        }

        public String getName() {
            return name;
        }

        public String getPassword() {
            return password;
        }

        public long getLastTimeAuthenticatedWithLDAP() {
            return lastTimeAuthenticatedWithLDAP;
        }

        public List<ResourcePermission> getRoles() {
            return roles;
        }

        public static final class Builder {
            private String name;
            private String password;
            private long lastTimeAuthenticatedWithLDAP;

            private List<ResourcePermission> roles;

            private Builder() {
            }

            public Builder withName(String name) {
                this.name = name;
                return this;
            }

            public Builder withPassword(String password) {
                this.password = password;
                return this;
            }

            public Builder withLastTimeAuthenticatedWithLDAP(long lastTimeAuthenticatedWithLDAP) {
                this.lastTimeAuthenticatedWithLDAP = lastTimeAuthenticatedWithLDAP;
                return this;
            }

            public Builder withRoles(List<ResourcePermission> roles) {
                this.roles = roles;
                return this;
            }

            public User build() {
                return new User(this);
            }
        }
    }
}
