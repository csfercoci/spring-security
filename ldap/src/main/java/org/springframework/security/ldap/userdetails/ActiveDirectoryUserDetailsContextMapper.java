package org.springframework.security.ldap.userdetails;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapProperties; // Assuming properties might be needed for some default behaviors or attribute names
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.Arrays;


public class ActiveDirectoryUserDetailsContextMapper implements UserDetailsContextMapper {

    // Constants for userAccountControl flags (values from Microsoft documentation)
    private static final int UF_SCRIPT = 0x0001; // Logon script executed
    private static final int UF_ACCOUNTDISABLE = 0x0002;
    private static final int UF_HOMEDIR_REQUIRED = 0x0008;
    private static final int UF_LOCKOUT = 0x0010;
    private static final int UF_PASSWD_NOTREQD = 0x0020;
    private static final int UF_PASSWD_CANT_CHANGE = 0x0040; // User cannot change password
    // UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x0080; (Not typically used for status)
    private static final int UF_TEMP_DUPLICATE_ACCOUNT = 0x0100; // Local user account
    private static final int UF_NORMAL_ACCOUNT = 0x0200; // Typical account
    private static final int UF_INTERDOMAIN_TRUST_ACCOUNT = 0x0800;
    private static final int UF_WORKSTATION_TRUST_ACCOUNT = 0x1000;
    private static final int UF_SERVER_TRUST_ACCOUNT = 0x2000;
    private static final int UF_DONT_EXPIRE_PASSWD = 0x10000; // Password never expires
    private static final int UF_MNS_LOGON_ACCOUNT = 0x20000;
    private static final int UF_SMARTCARD_REQUIRED = 0x40000;
    private static final int UF_TRUSTED_FOR_DELEGATION = 0x80000;
    private static final int UF_NOT_DELEGATED = 0x100000;
    private static final int UF_USE_DES_KEY_ONLY = 0x200000;
    private static final int UF_DONT_REQ_PREAUTH = 0x400000;
    private static final int UF_PASSWORD_EXPIRED = 0x800000; // Password has expired (set by system)
    // UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x1000000; (Not typically used for status)
    // UF_NO_AUTH_DATA_REQUIRED = 0x2000000;
    // UF_PARTIAL_SECRETS_ACCOUNT = 0x04000000;
    // UF_USE_AES_KEYS = 0x08000000;


    private final ActiveDirectoryLdapProperties adProperties;
    private LdapAuthoritiesPopulator authoritiesPopulator; // To populate groups

    public ActiveDirectoryUserDetailsContextMapper(ActiveDirectoryLdapProperties adProperties, LdapAuthoritiesPopulator authoritiesPopulator) {
        Assert.notNull(adProperties, "adProperties must not be null");
        Assert.notNull(authoritiesPopulator, "authoritiesPopulator must not be null");
        this.adProperties = adProperties;
        this.authoritiesPopulator = authoritiesPopulator;
    }

    // Alternative constructor if a default populator is desired or authorities are handled differently
    public ActiveDirectoryUserDetailsContextMapper(ActiveDirectoryLdapProperties adProperties) {
        Assert.notNull(adProperties, "adProperties must not be null");
        this.adProperties = adProperties;
        // Default populator could be new DefaultLdapAuthoritiesPopulator(contextSource, groupSearchBase)
        // but that requires ContextSource and groupSearchBase.
        // For now, let's require it to be injected or default to no authorities.
        this.authoritiesPopulator = (ctx, username) -> AuthorityUtils.NO_AUTHORITIES;
    }


    @Override
    public UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authoritiesFromAuthProvider) {
        // The 'authoritiesFromAuthProvider' are typically those granted by the authentication provider itself (e.g. based on bind DN).
        // We will use LdapAuthoritiesPopulator to get authorities based on user's attributes (e.g. memberOf).

        String dn = ctx.getNameInNamespace();
        String sAMAccountName = ctx.getStringAttribute("sAMAccountName");
        if (sAMAccountName == null) {
            sAMAccountName = username; // Fallback, though sAMAccountName should ideally be present
        }

        int userAccountControl = 0;
        String uacString = ctx.getStringAttribute("userAccountControl");
        if (StringUtils.hasText(uacString)) {
            userAccountControl = Integer.parseInt(uacString);
        }

        boolean adAccountIsDisabled = (userAccountControl & UF_ACCOUNTDISABLE) != 0;
        boolean adAccountIsLocked = (userAccountControl & UF_LOCKOUT) != 0;

        long accountExpiresFileTime = 0;
        String accountExpiresString = ctx.getStringAttribute("accountExpires");
        if (StringUtils.hasText(accountExpiresString)) {
            try {
                accountExpiresFileTime = Long.parseLong(accountExpiresString);
            } catch (NumberFormatException e) {
                // Log or handle malformed attribute
            }
        }

        boolean adAccountExpires = false; // Represents if the AD account itself is expired
        if (accountExpiresFileTime != 0 && accountExpiresFileTime < Long.MAX_VALUE) { // 0 or MAX means never expires
            long currentTimeMillis = System.currentTimeMillis();
            long accountExpiresMillis = fileTimeUtcToMillis(accountExpiresFileTime);
            if (accountExpiresMillis < currentTimeMillis) {
                adAccountExpires = true;
            }
        }

        boolean adPasswordNeverExpires = (userAccountControl & UF_DONT_EXPIRE_PASSWD) != 0;

        long pwdLastSetFileTime = 0;
        String pwdLastSetString = ctx.getStringAttribute("pwdLastSet");
        if (StringUtils.hasText(pwdLastSetString)) {
             try {
                pwdLastSetFileTime = Long.parseLong(pwdLastSetString);
            } catch (NumberFormatException e) {
                // Log or handle malformed attribute
            }
        }
        LocalDateTime adPasswordLastSet = null;
        if (pwdLastSetFileTime > 0) {
            adPasswordLastSet = fileTimeUtcToLocalDateTime(pwdLastSetFileTime);
        }

        boolean adPasswordMustChange = (pwdLastSetFileTime == 0) || ((userAccountControl & UF_PASSWORD_EXPIRED) != 0);
        if (adPasswordNeverExpires) {
            adPasswordMustChange = false;
        }

        String adDisplayName = ctx.getStringAttribute("displayName");
        String adUserPrincipalName = ctx.getStringAttribute("userPrincipalName");
        String adMail = ctx.getStringAttribute("mail");

        Collection<? extends GrantedAuthority> finalAuthorities = this.authoritiesPopulator.getGrantedAuthorities(ctx, sAMAccountName);

        // Standard UserDetails flags derived from AD attributes
        boolean enabled = !adAccountIsDisabled;
        boolean accountNonExpired = !adAccountExpires;
        boolean credentialsNonExpired = !adPasswordMustChange;
        boolean accountNonLocked = !adAccountIsLocked;

        // Using the constructor from ActiveDirectoryUserDetailsImpl that takes detailed AD flags
        return new ActiveDirectoryUserDetailsImpl(
                sAMAccountName,
                "[PROTECTED]",
                finalAuthorities,
                enabled,
                accountNonExpired,
                credentialsNonExpired,
                accountNonLocked,
                dn,
                adPasswordLastSet,
                adDisplayName,
                sAMAccountName,
                adUserPrincipalName,
                adMail,
                userAccountControl,      // raw userAccountControl
                adAccountIsLocked,       // AD specific: is account locked
                adAccountIsDisabled,     // AD specific: is account disabled (redundant with !enabled but for clarity)
                adAccountExpires,        // AD specific: does the account itself expire (from accountExpires attr)
                adPasswordMustChange,    // AD specific: must password be changed
                adPasswordNeverExpires   // AD specific: password never expires flag
        );
    }

    @Override
    public void mapUserToContext(UserDetails user, DirContextOperations ctx) {
        throw new UnsupportedOperationException("ActiveDirectoryUserDetailsContextMapper does not support writing to LDAP.");
    }

    public static LocalDateTime fileTimeUtcToLocalDateTime(long fileTime) {
        if (fileTime == 0) return null;
        long epochDiff = 116444736000000000L;
        long millisSinceEpoch = (fileTime - epochDiff) / 10000;
        return LocalDateTime.ofInstant(Instant.ofEpochMilli(millisSinceEpoch), ZoneId.systemDefault());
    }

    public static long fileTimeUtcToMillis(long fileTime) {
        if (fileTime == 0) return 0;
        long epochDiff = 116444736000000000L;
        return (fileTime - epochDiff) / 10000;
    }
}
