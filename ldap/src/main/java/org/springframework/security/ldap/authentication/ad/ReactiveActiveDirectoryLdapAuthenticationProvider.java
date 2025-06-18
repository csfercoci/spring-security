package org.springframework.security.ldap.authentication.ad;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication; // Keep
import org.springframework.security.core.userdetails.UserDetails; // Keep, but will be ActiveDirectoryUserDetails
import org.springframework.security.ldap.userdetails.ReactiveActiveDirectoryLdapUserProfilePopulator;
import org.springframework.security.authentication.AbstractUserDetailsReactiveAuthenticationManager;
import org.springframework.security.ldap.userdetails.ActiveDirectoryUserDetails; // Import new type
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import org.springframework.util.Assert;

import javax.naming.AuthenticationException; // Keep
import javax.naming.Context; // Keep
import javax.naming.NamingException; // Keep
import javax.naming.directory.DirContext; // Keep
import javax.naming.ldap.InitialLdapContext; // Keep
import java.util.Hashtable; // Keep
import java.util.Locale; // Keep
import org.springframework.ldap.support.LdapUtils; // Keep


public class ReactiveActiveDirectoryLdapAuthenticationProvider extends AbstractUserDetailsReactiveAuthenticationManager {

    private final ReactiveActiveDirectoryLdapUserProfilePopulator userProfilePopulator;
    private final ActiveDirectoryLdapProperties adProperties;

    public ReactiveActiveDirectoryLdapAuthenticationProvider(
            ActiveDirectoryLdapProperties adProperties,
            ReactiveActiveDirectoryLdapUserProfilePopulator userProfilePopulator) {
        Assert.notNull(adProperties, "adProperties cannot be null");
        Assert.hasText(adProperties.getUrl(), "LDAP URL in adProperties must not be empty or null");
        Assert.notNull(userProfilePopulator, "userProfilePopulator cannot be null");

        this.adProperties = adProperties;
        this.userProfilePopulator = userProfilePopulator;
    }

    @Override
    protected Mono<UserDetails> retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) {
        String password = (String) authentication.getCredentials();
        // Use our static inner StringUtils class or ensure Spring's StringUtils is available
        if (!ReactiveActiveDirectoryLdapAuthenticationProvider.StringUtils.hasText(password)) {
            return Mono.error(new BadCredentialsException("Password must not be empty"));
        }

        String bindPrincipal = createBindPrincipal(username);

        return Mono.fromCallable(() -> bindAsUser(bindPrincipal, password))
            .subscribeOn(Schedulers.boundedElastic())
            .flatMap(boundContext -> {
                try {
                    // userProfilePopulator now returns Mono<ActiveDirectoryUserDetails>
                    // This is assignable to Mono<UserDetails> as ActiveDirectoryUserDetails extends UserDetails.
                    return this.userProfilePopulator.populateUser(username)
                        .doFinally(signalType -> LdapUtils.closeContext(boundContext));
                } catch (Exception e) {
                    LdapUtils.closeContext(boundContext);
                    return Mono.error(e);
                }
            })
            .onErrorMap(NamingException.class, ex -> {
                return new BadCredentialsException("Authentication failed for user: " + username, ex);
            });
    }

    private DirContext bindAsUser(String bindPrincipal, String password) throws NamingException {
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, bindPrincipal);
        env.put(Context.PROVIDER_URL, this.adProperties.getUrl());
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

        try {
            return new InitialLdapContext(env, null);
        } catch (AuthenticationException ex) {
            throw ex;
        }
    }

    String createBindPrincipal(String username) { // Package-private for potential testing access
        String currentDomain = this.adProperties.getDomain();
        if (currentDomain == null ||
            username.toLowerCase(Locale.ROOT).endsWith("." + currentDomain.toLowerCase(Locale.ROOT)) ||
            username.contains("@")) {
            return username;
        }
        return username + "@" + currentDomain;
    }

    public String createBindPrincipalForTest(String username) {
        return createBindPrincipal(username);
    }

    public static class StringUtils {
       public static boolean hasText(String str) {
           return str != null && !str.trim().isEmpty();
       }
    }
}
