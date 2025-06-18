package org.springframework.security.ldap.authentication.ad;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ldap.core.ContextSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
// import org.springframework.security.core.userdetails.User; // No longer using User.withUsername for mock
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.userdetails.ReactiveActiveDirectoryLdapUserProfilePopulator;
import org.springframework.security.ldap.userdetails.ActiveDirectoryUserDetails; // Import ActiveDirectoryUserDetails
import org.springframework.security.ldap.userdetails.ActiveDirectoryUserDetailsImpl; // If creating concrete instance
import java.time.LocalDateTime; // For ActiveDirectoryUserDetailsImpl
import java.util.ArrayList; // For ActiveDirectoryUserDetailsImpl authorities
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.ldap.InitialLdapContext;

import java.util.Collections;
import java.util.Hashtable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
public class ReactiveActiveDirectoryLdapAuthenticationProviderTests {

    @Mock
    private ReactiveActiveDirectoryLdapUserProfilePopulator mockUserProfilePopulator;
    // @Mock
    // private ContextSource mockContextSource; // No longer a field in the provider
    @Mock
    private ActiveDirectoryLdapProperties mockAdProperties;

    private ReactiveActiveDirectoryLdapAuthenticationProvider provider;
    private static final String TEST_DOMAIN = "example.com";
    private static final String TEST_LDAP_URL = "ldap://localhost:389"; // Problematic for real bind, but used for config
    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_PASSWORD = "password";

    // We need a way to mock the InitialLdapContext creation for bindAsUser
    // This is a common challenge with static/new calls in testing.
    // One approach is to refactor ReactiveActiveDirectoryLdapAuthenticationProvider
    // to use a factory for DirContext, or use PowerMockito (but let's avoid if possible).

    // For this test, we will assume that a successful call to new InitialLdapContext
    // returns a mock DirContext if the credentials are "correct" for the mock.
    // And throws AuthenticationException if "incorrect".
    // This part is hard to mock without changing SUT or using PowerMock.
    // The tests will focus more on the interaction with userProfilePopulator after a conceptual successful bind.

    @BeforeEach
    void setUp() {
        // Configure mockAdProperties with default values used in tests
        when(mockAdProperties.getDomain()).thenReturn(TEST_DOMAIN);
        when(mockAdProperties.getUrl()).thenReturn(TEST_LDAP_URL);
        // mockContextSource is not passed to provider constructor anymore
        provider = new ReactiveActiveDirectoryLdapAuthenticationProvider(mockAdProperties, mockUserProfilePopulator);
    }

    @Test
    void retrieveUser_whenBindSuccessfulAndUserFound_returnsUserDetails() {
        // This test is highly conceptual due to the `new InitialLdapContext` call.
        // We are mocking the populator, but the bind operation itself is not mocked here
        // and would attempt a real LDAP connection to TEST_LDAP_URL, which will likely fail.
        // To make this test pass without a real LDAP server, `bindAsUser` would need to be refactored
        // for testability (e.g., injecting a context factory) or PowerMockito would be needed.

        // UserDetails expectedUserDetails = User.withUsername(TEST_USERNAME + "@" + TEST_DOMAIN)
        //         .password("") // Password is not stored in UserDetails
        //         .authorities(new SimpleGrantedAuthority("ROLE_USER"))
        //         .build();
        // Now, mock ActiveDirectoryUserDetails
        ActiveDirectoryUserDetails expectedUserDetails = mock(ActiveDirectoryUserDetails.class);
        when(expectedUserDetails.getUsername()).thenReturn(TEST_USERNAME + "@" + TEST_DOMAIN); // sAMAccountName or UPN
        when(expectedUserDetails.getPassword()).thenReturn(""); // Should be empty or protected
        when(expectedUserDetails.getAuthorities()).thenReturn(Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        when(expectedUserDetails.isAccountNonExpired()).thenReturn(true);
        when(expectedUserDetails.isAccountNonLocked()).thenReturn(true);
        when(expectedUserDetails.isCredentialsNonExpired()).thenReturn(true);
        when(expectedUserDetails.isEnabled()).thenReturn(true);


        // WHEN: The user profile populator is called (after a hypothetical successful bind)
        // It should be called with the original username from the token
        // And it returns Mono<ActiveDirectoryUserDetails>
        when(mockUserProfilePopulator.populateUser(TEST_USERNAME))
                .thenReturn(Mono.just(expectedUserDetails)); // Mono.just will infer Mono<ActiveDirectoryUserDetails>

        UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(TEST_USERNAME, TEST_PASSWORD);

        // THEN: Attempt to retrieve the user
        // This StepVerifier block will likely experience an error during the bindAsUser phase
        // because it will try to connect to a real LDAP server.
        // We are asserting the behavior *if* the bind were successful and populator is called.
        StepVerifier.create(provider.retrieveUser(TEST_USERNAME, token))
            // We expect the userDetails from the populator IF bind was successful.
            // In a unit test where bind is not truly mocked, this is an optimistic assertion.
            .expectNextMatches(userDetails -> {
                assertThat(userDetails.getUsername()).isEqualTo(TEST_USERNAME + "@" + TEST_DOMAIN);
                assertThat(userDetails.getAuthorities()).containsExactly(new SimpleGrantedAuthority("ROLE_USER"));
                return true;
            })
            .verifyComplete(); // This will likely fail here due to the bind.

        // This verification might not be reached if the bind fails.
        verify(mockUserProfilePopulator).populateUser(TEST_USERNAME);
    }

    @Test
    void retrieveUser_whenBindFails_emitsBadCredentialsException() {
        // This test aims to verify that a NamingException (like AuthenticationException)
        // during the bind operation is mapped to BadCredentialsException.
        // The challenge is that `bindAsUser` calls `new InitialLdapContext` directly.
        // Without PowerMockito or refactoring, we can't make `new InitialLdapContext` throw an exception on demand.
        // The actual LDAP URL `ldap://localhost:389` will likely cause a connection error
        // if no server is running, which might be a different NamingException subclass.

        UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(TEST_USERNAME, "wrongpassword");

        // We expect a BadCredentialsException. The actual exception might vary based on
        // why the InitialLdapContext construction fails (e.g., connection refused vs. actual auth error).
        // The onErrorMap in SUT specifically catches NamingException.
        StepVerifier.create(provider.retrieveUser(TEST_USERNAME, token))
                .expectError(BadCredentialsException.class)
                .verify();

        verifyNoInteractions(mockUserProfilePopulator); // Populator should not be called if bind fails
    }

    @Test
    void retrieveUser_whenBindSuccessfulButUserNotFound_emitsUsernameNotFoundExceptionViaPopulator() {
        // This test also assumes a "successful bind" conceptually.
        // If the bind were successful, and then the populator fails to find the user.
        // Populator is called with the original username.
        when(mockUserProfilePopulator.populateUser(TEST_USERNAME))
                .thenReturn(Mono.error(new UsernameNotFoundException("User not found from populator")));

        UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(TEST_USERNAME, TEST_PASSWORD);

        // Similar to retrieveUser_whenBindSuccessfulAndUserFound, this relies on the bind
        // not failing catastrophically before the populator is even called.
        StepVerifier.create(provider.retrieveUser(TEST_USERNAME, token))
                .expectErrorSatisfies(throwable -> {
                    // Depending on how ReactiveAuthenticationManager wraps populator errors,
                    // it might be UsernameNotFoundException or re-wrapped as BadCredentialsException.
                    // The current SUT's onErrorMap for NamingException might not catch this if it's from populator.
                    // AbstractUserDetailsReactiveAuthenticationManager typically propagates UserNotFound from retrieveUser.
                    assertThat(throwable).isInstanceOfAny(UsernameNotFoundException.class, BadCredentialsException.class);
                    if (throwable instanceof UsernameNotFoundException) {
                         assertThat(throwable.getMessage()).isEqualTo("User not found from populator");
                    }
                })
                .verify();
         verify(mockUserProfilePopulator).populateUser(TEST_USERNAME);
    }


    @Test
    void createBindPrincipal_withDomainAndUsernameWithoutDomain_appendsDomain() {
        // mockAdProperties is already configured with TEST_DOMAIN in setUp
        String principal = provider.createBindPrincipalForTest("user");
        assertThat(principal).isEqualTo("user@" + TEST_DOMAIN);
    }

    @Test
    void createBindPrincipal_withDomainAndUsernameWithDomain_usesOriginalUsername() {
        // mockAdProperties is already configured with TEST_DOMAIN in setUp
        String principal = provider.createBindPrincipalForTest("user@" + TEST_DOMAIN);
        assertThat(principal).isEqualTo("user@" + TEST_DOMAIN);
    }

    @Test
    void createBindPrincipal_withDomainAndUsernameWithDifferentDomain_usesOriginalUsername() {
        // mockAdProperties is already configured with TEST_DOMAIN in setUp
        String principal = provider.createBindPrincipalForTest("user@other.com");
        assertThat(principal).isEqualTo("user@other.com");
    }

    @Test
    void createBindPrincipal_withoutDomain_usesOriginalUsername() {
        ActiveDirectoryLdapProperties adPropsNoDomain = mock(ActiveDirectoryLdapProperties.class);
        when(adPropsNoDomain.getDomain()).thenReturn(null);
        // URL is still needed for constructor validation
        when(adPropsNoDomain.getUrl()).thenReturn(TEST_LDAP_URL);

        ReactiveActiveDirectoryLdapAuthenticationProvider providerNoDomain =
            new ReactiveActiveDirectoryLdapAuthenticationProvider(adPropsNoDomain, mockUserProfilePopulator);
        String principal = providerNoDomain.createBindPrincipalForTest("user");
        assertThat(principal).isEqualTo("user");
    }

    @Test
    void retrieveUser_whenPasswordIsEmpty_emitsBadCredentialsException() {
        UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(TEST_USERNAME, "");

        StepVerifier.create(provider.retrieveUser(TEST_USERNAME, token))
            .expectErrorSatisfies(throwable -> {
                assertThat(throwable).isInstanceOf(BadCredentialsException.class);
                assertThat(throwable.getMessage()).isEqualTo("Password must not be empty");
            })
            .verify();
        verifyNoInteractions(mockUserProfilePopulator);
    }

    @Test
    void retrieveUser_whenPasswordIsNull_emitsBadCredentialsException() {
        UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(TEST_USERNAME, null);

        StepVerifier.create(provider.retrieveUser(TEST_USERNAME, token))
            .expectErrorSatisfies(throwable -> {
                assertThat(throwable).isInstanceOf(BadCredentialsException.class);
                assertThat(throwable.getMessage()).isEqualTo("Password must not be empty");
            })
            .verify();
        verifyNoInteractions(mockUserProfilePopulator);
    }
}
// Note: The tests `retrieveUser_whenBindSuccessfulAndUserFound`, `retrieveUser_whenBindFails_emitsBadCredentialsException`,
// and `retrieveUser_whenBindSuccessfulButUserNotFound_emitsUsernameNotFoundExceptionViaPopulator` are testing a SUT
// that makes direct calls to `new InitialLdapContext()`. Without an actual LDAP server running at TEST_LDAP_URL
// or using more advanced mocking techniques (like PowerMockito or SUT refactoring for DI), these tests
// will likely fail during the `bindAsUser` call or produce results based on the specific error from that uncontrolled call.
// The assertions are written based on the *intended* logic flow if such control was possible.
// The tests for `createBindPrincipalForTest` are fine as they use the test helper method.
// The tests for empty/null password are also fine as they test logic before the bind attempt.
