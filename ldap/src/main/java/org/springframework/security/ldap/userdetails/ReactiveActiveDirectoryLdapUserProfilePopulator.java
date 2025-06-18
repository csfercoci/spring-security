package org.springframework.security.ldap.userdetails;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority; // Needed for the inline LdapAuthoritiesPopulator
import org.springframework.security.core.userdetails.UserDetails;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.naming.directory.SearchControls;
import org.springframework.ldap.core.ContextSource;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.util.Assert;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapProperties;

import java.util.HashSet; // Needed for the inline LdapAuthoritiesPopulator
import java.util.Set; // Needed for the inline LdapAuthoritiesPopulator


public class ReactiveActiveDirectoryLdapUserProfilePopulator {

    private final ContextSource contextSource;
    private final ActiveDirectoryLdapProperties adProperties;
    private final ActiveDirectoryUserDetailsContextMapper userDetailsMapper; // New field for the mapper

    public ReactiveActiveDirectoryLdapUserProfilePopulator(
            ContextSource contextSource,
            ActiveDirectoryLdapProperties adProperties) {
        Assert.notNull(contextSource, "contextSource must not be null");
        Assert.notNull(adProperties, "adProperties must not be null");
        this.contextSource = contextSource;
        this.adProperties = adProperties;

        // This LdapAuthoritiesPopulator implementation reads 'memberOf' attribute from the user's context
        // and maps group DNs to GrantedAuthority objects.
        LdapAuthoritiesPopulator memberOfPopulator = (userContext, username) -> {
            Set<GrantedAuthority> authorities = new HashSet<>();
            String[] groupDns = userContext.getStringAttributes(this.adProperties.getMemberOfAttribute());
            if (groupDns != null) {
                for (String groupDn : groupDns) {
                    try {
                        javax.naming.ldap.LdapName ldapName = new javax.naming.ldap.LdapName(groupDn);
                        String groupName = ldapName.getRdns().stream()
                            .filter(rdn -> rdn.getType().equalsIgnoreCase(this.adProperties.getGroupRoleAttribute()))
                            .findFirst()
                            .map(rdn -> String.valueOf(rdn.getValue()))
                            .orElse(groupDn); // Fallback to full DN if attribute not found
                        authorities.add(new SimpleGrantedAuthority(this.adProperties.getRolePrefix() + groupName.toUpperCase()));
                    } catch (javax.naming.InvalidNameException e) {
                        // Consider logging this error, e.g., using a logger field
                        // System.err.println("Failed to parse group DN: " + groupDn + " - " + e.getMessage());
                    }
                }
            }
            return authorities;
        };

        this.userDetailsMapper = new ActiveDirectoryUserDetailsContextMapper(this.adProperties, memberOfPopulator);
    }

    // Constructor allowing injection of a pre-configured mapper
    public ReactiveActiveDirectoryLdapUserProfilePopulator(
            ContextSource contextSource,
            ActiveDirectoryLdapProperties adProperties,
            ActiveDirectoryUserDetailsContextMapper userDetailsMapper) {
        Assert.notNull(contextSource, "contextSource must not be null");
        Assert.notNull(adProperties, "adProperties must not be null");
        Assert.notNull(userDetailsMapper, "userDetailsMapper must not be null");
        this.contextSource = contextSource;
        this.adProperties = adProperties;
        this.userDetailsMapper = userDetailsMapper;
    }


    public Mono<ActiveDirectoryUserDetails> populateUser(String username) { // Return type changed
        return Mono.fromCallable(() -> {
            SpringSecurityLdapTemplate ldapTemplate = new SpringSecurityLdapTemplate(this.contextSource);
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            // Attributes to retrieve can be specified here if needed, e.g. searchControls.setReturningAttributes(...)
            // By default, it retrieves all user attributes. Mapper will pick what it needs.

            DirContextOperations userContext = ldapTemplate.searchForSingleEntry(
                    this.adProperties.getUserSearchBase(),
                    this.adProperties.getUserSearchFilter(),
                    new String[]{username});

            // Use the mapper to create UserDetails. Authorities are handled by the mapper's populator.
            // The 'authoritiesFromAuthProvider' argument to mapUserFromContext is null here,
            // as we are not in an authentication provider context that would pass pre-authenticated authorities.
            // The username passed to mapUserFromContext is the one used for the search (which might be sAMAccountName).
            ActiveDirectoryUserDetails userDetails = (ActiveDirectoryUserDetails) this.userDetailsMapper.mapUserFromContext(userContext, username, null);

            return userDetails;
        }).cast(ActiveDirectoryUserDetails.class) // Ensure correct Mono type
          .switchIfEmpty(Mono.error(new org.springframework.security.core.userdetails.UsernameNotFoundException("User " + username + " not found in Active Directory")));
    }

    // This method might be less relevant now as the primary UserDetails object is ActiveDirectoryUserDetails,
    // which already contains the authorities.
    public Flux<GrantedAuthority> populateGroups(ActiveDirectoryUserDetails user) {
        Assert.notNull(user, "ActiveDirectoryUserDetails cannot be null");
        return Flux.fromIterable(user.getAuthorities());
    }

    // mapGroupDnToAuthority and its test hook are removed as this logic is now
    // encapsulated within the LdapAuthoritiesPopulator supplied to the ActiveDirectoryUserDetailsContextMapper.
}
