package org.springframework.security.ldap.userdetails;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapProperties;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.concurrent.TimeUnit;


import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ActiveDirectoryUserDetailsContextMapperTests {

    @Mock
    private DirContextOperations mockCtx;
    @Mock
    private ActiveDirectoryLdapProperties mockAdProperties;
    @Mock
    private LdapAuthoritiesPopulator mockAuthoritiesPopulator;

    private ActiveDirectoryUserDetailsContextMapper mapper;

    // userAccountControl flags
    private static final int UF_ACCOUNTDISABLE = 0x0002;
    private static final int UF_LOCKOUT = 0x0010;
    private static final int UF_DONT_EXPIRE_PASSWD = 0x10000;
    private static final int UF_PASSWORD_EXPIRED_FLAG = 0x800000; // System set if password has expired
    private static final int UF_NORMAL_ACCOUNT = 0x0200;

    @BeforeEach
    void setUp() {
        mapper = new ActiveDirectoryUserDetailsContextMapper(mockAdProperties, mockAuthoritiesPopulator);

        when(mockAdProperties.getMemberOfAttribute()).thenReturn("memberOf"); // Though not directly used by mapper
        when(mockAdProperties.getRolePrefix()).thenReturn("ROLE_"); // Used by populator, not directly by mapper
        when(mockAdProperties.getGroupRoleAttribute()).thenReturn("cn"); // Used by populator

        Collection<GrantedAuthority> defaultAuthorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        when(mockAuthoritiesPopulator.getGrantedAuthorities(any(DirContextOperations.class), anyString()))
                .thenReturn(defaultAuthorities);

        when(mockCtx.getNameInNamespace()).thenReturn("CN=Test User,OU=Users,DC=example,DC=com");
        when(mockCtx.getStringAttribute("sAMAccountName")).thenReturn("testuser");
        // Provide default for accountExpires to avoid NPE if not set explicitly by a test
        when(mockCtx.getStringAttribute("accountExpires")).thenReturn("0"); // Default to never expires
    }

    private void setupUserAccountControl(int uacValue) {
        when(mockCtx.getStringAttribute("userAccountControl")).thenReturn(String.valueOf(uacValue));
    }

    private void setupPwdLastSet(long pwdLastSetValue) {
        when(mockCtx.getStringAttribute("pwdLastSet")).thenReturn(String.valueOf(pwdLastSetValue));
    }

    private void setupAccountExpires(long accountExpiresValue) {
        when(mockCtx.getStringAttribute("accountExpires")).thenReturn(String.valueOf(accountExpiresValue));
    }

    @Test
    void mapUserFromContext_mapsBasicAttributesCorrectly() {
        setupUserAccountControl(UF_NORMAL_ACCOUNT);
        // Set pwdLastSet to a recent time (e.g., equivalent to now)
        long nowInFileTime = (System.currentTimeMillis() * 10000L) + 116444736000000000L;
        setupPwdLastSet(nowInFileTime);
        // setupAccountExpires(0); // Defaulted in setup

        when(mockCtx.getStringAttribute("displayName")).thenReturn("Test Display Name");
        when(mockCtx.getStringAttribute("userPrincipalName")).thenReturn("testuser@example.com");
        when(mockCtx.getStringAttribute("mail")).thenReturn("testuser@example.com");

        ActiveDirectoryUserDetails userDetails = (ActiveDirectoryUserDetails) mapper.mapUserFromContext(mockCtx, "testuser", null);

        assertThat(userDetails.getUsername()).isEqualTo("testuser"); // sAMAccountName
        assertThat(userDetails.getDisplayName()).isEqualTo("Test Display Name");
        assertThat(userDetails.getUserPrincipalName()).isEqualTo("testuser@example.com");
        assertThat(userDetails.getMail()).isEqualTo("testuser@example.com");
        assertThat(userDetails.getAuthorities()).containsExactly(new SimpleGrantedAuthority("ROLE_USER"));
        assertThat(userDetails.getUserAccountControl()).isEqualTo(UF_NORMAL_ACCOUNT);
    }

    @Test
    void mapUserFromContext_accountDisabled() {
        setupUserAccountControl(UF_ACCOUNTDISABLE);
        ActiveDirectoryUserDetails userDetails = (ActiveDirectoryUserDetails) mapper.mapUserFromContext(mockCtx, "testuser", null);
        assertThat(userDetails.isEnabled()).isFalse();
        assertThat(userDetails.isAccountDisabled()).isTrue();
    }

    @Test
    void mapUserFromContext_accountLocked() {
        setupUserAccountControl(UF_LOCKOUT);
        ActiveDirectoryUserDetails userDetails = (ActiveDirectoryUserDetails) mapper.mapUserFromContext(mockCtx, "testuser", null);
        assertThat(userDetails.isAccountNonLocked()).isFalse();
        assertThat(userDetails.isAccountLocked()).isTrue();
    }

    @Test
    void mapUserFromContext_passwordNeverExpires() {
        setupUserAccountControl(UF_DONT_EXPIRE_PASSWD);
        ActiveDirectoryUserDetails userDetails = (ActiveDirectoryUserDetails) mapper.mapUserFromContext(mockCtx, "testuser", null);
        assertThat(userDetails.isPasswordNeverExpires()).isTrue();
        assertThat(userDetails.isCredentialsNonExpired()).isTrue();
        assertThat(userDetails.isPasswordExpired()).isFalse();
    }

    @Test
    void mapUserFromContext_passwordExpired_pwdLastSetZero() {
        setupPwdLastSet(0);
        ActiveDirectoryUserDetails userDetails = (ActiveDirectoryUserDetails) mapper.mapUserFromContext(mockCtx, "testuser", null);
        assertThat(userDetails.isPasswordExpired()).isTrue();
        assertThat(userDetails.isCredentialsNonExpired()).isFalse();
        assertThat(userDetails.getPasswordLastSet()).isNull();
    }

    @Test
    void mapUserFromContext_passwordExpired_uacFlagSet() {
        setupUserAccountControl(UF_PASSWORD_EXPIRED_FLAG);
        long somePastTime = ((System.currentTimeMillis() - TimeUnit.DAYS.toMillis(90)) * 10000L) + 116444736000000000L;
        setupPwdLastSet(somePastTime); // Ensure pwdLastSet is not 0, so UF_PASSWORD_EXPIRED is the cause

        ActiveDirectoryUserDetails userDetails = (ActiveDirectoryUserDetails) mapper.mapUserFromContext(mockCtx, "testuser", null);
        assertThat(userDetails.isPasswordExpired()).isTrue();
        assertThat(userDetails.isCredentialsNonExpired()).isFalse();
    }

    @Test
    void mapUserFromContext_passwordNotExpired_validPwdLastSet() {
        long nowFileTime = (System.currentTimeMillis() * 10000L) + 116444736000000000L;
        setupPwdLastSet(nowFileTime);
        setupUserAccountControl(UF_NORMAL_ACCOUNT); // No overriding expiry flags

        ActiveDirectoryUserDetails userDetails = (ActiveDirectoryUserDetails) mapper.mapUserFromContext(mockCtx, "testuser", null);

        assertThat(userDetails.isPasswordExpired()).isFalse();
        assertThat(userDetails.isCredentialsNonExpired()).isTrue();
        assertThat(userDetails.getPasswordLastSet()).isNotNull();
        // Check if conversion is roughly correct (to the second)
        assertThat(userDetails.getPasswordLastSet().toEpochSecond(ZoneOffset.UTC))
            .isEqualTo(LocalDateTime.now().toEpochSecond(ZoneOffset.UTC));
    }

    @Test
    void mapUserFromContext_accountExpires_past() {
        long expiredFileTime = ((System.currentTimeMillis() - TimeUnit.DAYS.toMillis(1)) * 10000L) + 116444736000000000L;
        setupAccountExpires(expiredFileTime);
        ActiveDirectoryUserDetails userDetails = (ActiveDirectoryUserDetails) mapper.mapUserFromContext(mockCtx, "testuser", null);
        assertThat(userDetails.isAccountExpired()).isTrue();
        assertThat(userDetails.isAccountNonExpired()).isFalse();
    }

    @Test
    void mapUserFromContext_accountExpires_future() {
        long futureFileTime = ((System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1)) * 10000L) + 116444736000000000L;
        setupAccountExpires(futureFileTime);
        ActiveDirectoryUserDetails userDetails = (ActiveDirectoryUserDetails) mapper.mapUserFromContext(mockCtx, "testuser", null);
        assertThat(userDetails.isAccountExpired()).isFalse();
        assertThat(userDetails.isAccountNonExpired()).isTrue();
    }

    @Test
    void mapUserFromContext_accountExpires_zeroOrMaxMeansNever() {
        setupAccountExpires(0);
        ActiveDirectoryUserDetails userDetails1 = (ActiveDirectoryUserDetails) mapper.mapUserFromContext(mockCtx, "testuser", null);
        assertThat(userDetails1.isAccountExpired()).isFalse();
        assertThat(userDetails1.isAccountNonExpired()).isTrue();

        setupAccountExpires(Long.MAX_VALUE);
        ActiveDirectoryUserDetails userDetails2 = (ActiveDirectoryUserDetails) mapper.mapUserFromContext(mockCtx, "testuser", null);
        assertThat(userDetails2.isAccountExpired()).isFalse();
        assertThat(userDetails2.isAccountNonExpired()).isTrue();
    }

    @Test
    void mapUserFromContext_usesCustomAuthoritiesPopulator() {
        Collection<GrantedAuthority> customAuthorities = Arrays.asList(
            new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_MANAGER")
        );
        when(mockAuthoritiesPopulator.getGrantedAuthorities(any(DirContextOperations.class), anyString()))
            .thenReturn(customAuthorities);

        ActiveDirectoryUserDetails userDetails = (ActiveDirectoryUserDetails) mapper.mapUserFromContext(mockCtx, "testuser", null);
        assertThat(userDetails.getAuthorities()).containsExactlyInAnyOrderElementsOf(customAuthorities);
    }

    @Test
    void mapUserFromContext_sAMAccountNameIsNull_usesUsernameAsFallback() {
        when(mockCtx.getStringAttribute("sAMAccountName")).thenReturn(null);
        // All other attributes are fine
        setupUserAccountControl(UF_NORMAL_ACCOUNT);
        long nowInFileTime = (System.currentTimeMillis() * 10000L) + 116444736000000000L;
        setupPwdLastSet(nowInFileTime);
        when(mockCtx.getStringAttribute("displayName")).thenReturn("Test Display Name");

        ActiveDirectoryUserDetails userDetails = (ActiveDirectoryUserDetails) mapper.mapUserFromContext(mockCtx, "fallbackUser", null);

        // Username for UserDetails should be the fallback username
        assertThat(userDetails.getUsername()).isEqualTo("fallbackUser");
        // sAMAccountName attribute in UserDetails object should also be the fallback
        assertThat(userDetails.getSAMAccountName()).isEqualTo("fallbackUser");
        assertThat(userDetails.getDisplayName()).isEqualTo("Test Display Name");
    }

    @Test
    void mapUserFromContext_handlesNullAttributesGracefully() {
        // Setup only essential attributes
        when(mockCtx.getStringAttribute("sAMAccountName")).thenReturn("testuser");
        when(mockCtx.getNameInNamespace()).thenReturn("CN=Test User,DC=example,DC=com");
        setupUserAccountControl(UF_NORMAL_ACCOUNT);
        // All other string attributes (displayName, UPN, mail) will return null from mockCtx
        // pwdLastSet and accountExpires will return null then parsed as 0

        ActiveDirectoryUserDetails userDetails = (ActiveDirectoryUserDetails) mapper.mapUserFromContext(mockCtx, "testuser", null);

        assertThat(userDetails.getUsername()).isEqualTo("testuser");
        assertThat(userDetails.getDisplayName()).isNull();
        assertThat(userDetails.getUserPrincipalName()).isNull();
        assertThat(userDetails.getMail()).isNull();
        assertThat(userDetails.getPasswordLastSet()).isNull(); // Because pwdLastSet=0
        assertThat(userDetails.isAccountExpired()).isFalse(); // Because accountExpires=0
        assertThat(userDetails.isPasswordExpired()).isTrue(); // Because pwdLastSet=0
    }
}
