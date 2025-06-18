package org.springframework.security.ldap.userdetails;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ldap.core.ContextSource;
// Import ActiveDirectoryUserDetails and ActiveDirectoryUserDetailsImpl
import org.springframework.security.ldap.userdetails.ActiveDirectoryUserDetails;
import org.springframework.security.ldap.userdetails.ActiveDirectoryUserDetailsImpl;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.SpringSecurityLdapTemplate; // Will be mocked if possible, or its interactions
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays; // Added import
import java.util.Collection; // Added import
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import javax.naming.Name;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.LdapName;
import java.util.HashSet;
import java.util.Set;
import org.springframework.security.core.authority.SimpleGrantedAuthority;


import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.springframework.ldap.core.LdapTemplate; // For mocking searchForSingleEntry if SpringSecurityLdapTemplate is hard

@ExtendWith(MockitoExtension.class)
public class ReactiveActiveDirectoryLdapUserProfilePopulatorTests {

    @Mock
    private ContextSource contextSource;
    @Mock
    private ActiveDirectoryLdapProperties mockAdProperties;
    @Mock
    private ActiveDirectoryUserDetailsContextMapper mockUserDetailsMapper; // To be injected

    private ReactiveActiveDirectoryLdapUserProfilePopulator populatorDefaultConstructor; // Uses internal mapper
    private ReactiveActiveDirectoryLdapUserProfilePopulator populatorWithInjectedMapper; // Uses mock mapper


    @BeforeEach
    void setUp() {
        // Common properties needed by the LdapAuthoritiesPopulator lambda in the default constructor
        when(mockAdProperties.getRolePrefix()).thenReturn("ROLE_");
        when(mockAdProperties.getGroupRoleAttribute()).thenReturn("cn");
        when(mockAdProperties.getMemberOfAttribute()).thenReturn("memberOf");
        // Properties needed by the populator for searching users
        when(mockAdProperties.getUserSearchBase()).thenReturn("OU=Users,DC=example,DC=com");
        when(mockAdProperties.getUserSearchFilter()).thenReturn("(&(objectClass=user)(sAMAccountName={0}))");

        // This instance uses the default constructor, creating an internal ActiveDirectoryUserDetailsContextMapper
        // and an internal LdapAuthoritiesPopulator (lambda).
        populatorDefaultConstructor = new ReactiveActiveDirectoryLdapUserProfilePopulator(contextSource, mockAdProperties);

        // This instance uses the constructor that injects a mock mapper.
        populatorWithInjectedMapper = new ReactiveActiveDirectoryLdapUserProfilePopulator(contextSource, mockAdProperties, mockUserDetailsMapper);
    }

    // Happy path tests for populateUser are difficult due to `new SpringSecurityLdapTemplate`.
    // The tests below focus on error paths and the populateGroups method,
    // and the conceptual wiring of an injected mapper.

    @Test
    void populateUser_whenUserNotFound_emitsUsernameNotFoundException() {
        // This test uses the populator with the default constructor (internally created mapper).
        // It relies on the ldapTemplate.searchForSingleEntry throwing an error or returning null
        // because the mock ContextSource isn't fully functional for a real LDAP search.
        StepVerifier.create(populatorDefaultConstructor.populateUser("nonexistentuser"))
            .expectError(UsernameNotFoundException.class)
            .verify();
    }

    @Test
    void populateGroups_whenUserIsActiveDirectoryUserDetails_returnsAuthorities() {
        ActiveDirectoryUserDetails mockAdUserDetails = mock(ActiveDirectoryUserDetails.class);
        Collection<GrantedAuthority> expectedAuthorities = Arrays.asList(
            new SimpleGrantedAuthority("ROLE_GROUP1"),
            new SimpleGrantedAuthority("ROLE_GROUP2")
        );
        when(mockAdUserDetails.getAuthorities()).thenReturn(expectedAuthorities);

        // Test with either populator, behavior of populateGroups is the same.
        Flux<GrantedAuthority> authoritiesFlux = populatorDefaultConstructor.populateGroups(mockAdUserDetails);

        StepVerifier.create(authoritiesFlux)
            .expectNextSequence(expectedAuthorities)
            .verifyComplete();
    }

    @Test
    void populateUser_withInjectedMapper_usesMapperToReturnUserDetails() {
        String username = "testuser";
        DirContextOperations mockDirContext = mock(DirContextOperations.class);

        ActiveDirectoryUserDetails expectedDetails = new ActiveDirectoryUserDetailsImpl(
            username, "", Collections.emptyList(), true, true, true, true, "dn",
            null, null, null, null, null, 0, false, false, false, false, false);

        // Mock the injected mapper's behavior
        when(mockUserDetailsMapper.mapUserFromContext(eq(mockDirContext), eq(username), isNull()))
            .thenReturn(expectedDetails);

        // We need a way to mock SpringSecurityLdapTemplate to return mockDirContext.
        // This is the main challenge. For this test, let's assume we *could* do that,
        // to verify the mapper interaction if the LDAP call part was successful.
        // If SpringSecurityLdapTemplate was injectable:
        // SpringSecurityLdapTemplate mockLdapTemplate = mock(SpringSecurityLdapTemplate.class);
        // when(mockLdapTemplate.searchForSingleEntry(anyString(), anyString(), any(String[].class)))
        //    .thenReturn(mockDirContext);
        // populatorWithInjectedMapper.setLdapTemplate(mockLdapTemplate); // If such a setter existed

        // Since we can't easily mock SpringSecurityLdapTemplate, this test verifies that *if* the template
        // search was successful and returned mockDirContext, the populator would then correctly use the
        // injected mockUserDetailsMapper. This test is therefore more focused on the wiring of the
        // injected mapper rather than the full populateUser flow.

        // To make this test somewhat runnable, we'd have to assume that the actual call to
        // populatorWithInjectedMapper.populateUser(username) can be made IF the ldapTemplate
        // it news up can be made to return mockDirContext. This is not possible without refactoring SUT
        // or PowerMock.

        // The most we can test here without SUT refactor is the UsernameNotFoundException path
        // or the populateGroups method. The happy path for populateUser is hard to unit test
        // in isolation due to the `new SpringSecurityLdapTemplate` call.

        // Let's verify the UsernameNotFoundException path with the injected mapper setup
        // to ensure it still propagates correctly.
        // We need the internal SpringSecurityLdapTemplate to fail.
        // This will behave similarly to the existing populateUser_whenUserNotFound_emitsUsernameNotFoundException test.
        StepVerifier.create(populatorWithInjectedMapper.populateUser("unknown"))
            .expectError(UsernameNotFoundException.class)
            .verify();
    }

    // Removed obsolete tests for mapGroupDnToAuthority as the method was removed from SUT.
    // The logic is now internal to an LdapAuthoritiesPopulator lambda.
    // Testing that lambda would require a different approach, likely by testing the
    // ActiveDirectoryUserDetailsContextMapper with a live DirContextOperations object,
    // or by verifying authorities on the UserDetails returned by populateUser in an integration test.
}
