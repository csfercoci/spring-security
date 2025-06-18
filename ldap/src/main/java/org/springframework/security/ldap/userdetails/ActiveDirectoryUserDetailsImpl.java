package org.springframework.security.ldap.userdetails;

import org.springframework.security.core.GrantedAuthority;
import java.time.LocalDateTime;
import java.util.Collection;

public class ActiveDirectoryUserDetailsImpl extends LdapUserDetailsImpl implements ActiveDirectoryUserDetails {

    private static final long serialVersionUID = 600L; // Adjust as per Spring Security versions

    // AD specific fields
    private boolean accountLocked; // Direct from UF_LOCKOUT
    // isEnabled() from LdapUserDetailsImpl represents !UF_ACCOUNTDISABLE
    private boolean accountExpired; // AD account itself expired (e.g. from accountExpires attribute)
    private boolean passwordExpired; // Typically from pwdLastSet = 0 or UF_PASSWORD_EXPIRED (if set by admin)
    private boolean passwordNeverExpires; // From UF_DONT_EXPIRE_PASSWD

    private LocalDateTime passwordLastSet;
    private String displayName;
    private String sAMAccountName;
    private String userPrincipalName;
    private String mail;
    private int userAccountControl;

    // Constructor
    public ActiveDirectoryUserDetailsImpl(
            String username, String password, Collection<? extends GrantedAuthority> authorities,
            boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked,
            String dn,
            // AD Specific fields start here, populated by a mapper
            int adUserAccountControl, // Raw UAC value
            LocalDateTime adPasswordLastSet,
            String adDisplayName,
            String adSAMAccountName,
            String adUserPrincipalName,
            String adMail
            // Derived boolean flags from UAC will be set by the mapper logic before calling this constructor,
            // or this constructor could take UAC and derive them.
            // For now, let's assume mapper provides pre-derived flags for standard UserDetails params,
            // and we store the raw UAC and direct AD interpretations.
            ) {

        // The standard UserDetails flags (enabled, accountNonExpired, etc.)
        // will be determined by the mapper based on userAccountControl and other AD attributes.
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities, dn);

        this.userAccountControl = adUserAccountControl;
        this.passwordLastSet = adPasswordLastSet;
        this.displayName = adDisplayName;
        this.sAMAccountName = adSAMAccountName;
        this.userPrincipalName = adUserPrincipalName;
        this.mail = adMail;

        // Populate AD-specific boolean fields based on userAccountControl
        // These flags are often derived. Mapper can do this, or we do it here if UAC is passed.
        // Let's assume the mapper will derive these and pass them if they are simple boolean fields,
        // or we can set them here from UAC.
        // The constructor signature in the prompt passed pre-derived "adAccountLocked", "adAccountExpired" etc.
        // I'll adjust to match that pattern for now.
        // Re-adding those boolean params to constructor as per prompt, makes it large but matches request.
    }

    // Constructor as per the prompt's implied direct boolean flags for AD state:
     public ActiveDirectoryUserDetailsImpl(
            String username, String password, Collection<? extends GrantedAuthority> authorities,
            // Standard UserDetails flags (likely derived by mapper from AD attributes)
            boolean enabled,
            boolean accountNonExpired, // Standard UserDetails flag
            boolean credentialsNonExpired, // Standard UserDetails flag
            boolean accountNonLocked, // Standard UserDetails flag
            String dn,
            // AD Specific fields from attributes
            LocalDateTime adPasswordLastSet,
            String adDisplayName,
            String adSAMAccountName,
            String adUserPrincipalName,
            String adMail,
            int adUserAccountControl, // Raw UAC value
            // AD specific boolean interpretations (can be derived from UAC by mapper or here)
            boolean adAccountIsLocked, // From UF_LOCKOUT
            boolean adAccountIsDisabled, // From UF_ACCOUNTDISABLE (inverse of 'enabled') - redundant if 'enabled' is set correctly
            boolean adAccountExpires, // From accountExpires attribute (separate from UAC)
            boolean adPasswordMustChange, // From pwdLastSet=0 or UF_PASSWORD_EXPIRED
            boolean adPasswordNeverExpires // From UF_DONT_EXPIRE_PASSWD
            ) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities, dn);

        this.passwordLastSet = adPasswordLastSet;
        this.displayName = adDisplayName;
        this.sAMAccountName = adSAMAccountName;
        this.userPrincipalName = adUserPrincipalName;
        this.mail = adMail;
        this.userAccountControl = adUserAccountControl;

        // Store the direct AD interpretations
        this.accountLocked = adAccountIsLocked;
        // this.isAccountDisabled is a method using !super.isEnabled()
        this.accountExpired = adAccountExpires; // This is for AD's specific account expiry date
        this.passwordExpired = adPasswordMustChange;
        this.passwordNeverExpires = adPasswordNeverExpires;
    }


    @Override
    public boolean isAccountLocked() {
        // Directly reflects AD's LOCKOUT flag (UF_LOCKOUT)
        return this.accountLocked;
    }

    @Override
    public boolean isAccountDisabled() {
        // True if UF_ACCOUNTDISABLE flag is set in userAccountControl.
        // This should align with !super.isEnabled().
        return !super.isEnabled();
    }

    @Override
    public boolean isAccountExpired() {
        // This refers to AD's specific account expiration date (accountExpires attribute),
        // not a UAC flag. The super.isAccountNonExpired() is what this should contradict if expired.
        return this.accountExpired;
    }

    @Override
    public boolean isPasswordExpired() {
        // This can be due to pwdLastSet=0, or UF_PASSWORD_EXPIRED flag,
        // or if current time - pwdLastSet > maxPasswordAge from domain policy.
        // The `passwordExpired` field is set by mapper based on these.
        return this.passwordExpired;
    }

    @Override
    public boolean isPasswordNeverExpires() {
        // From UF_DONT_EXPIRE_PASSWD flag in userAccountControl
        return this.passwordNeverExpires;
    }

    @Override
    public LocalDateTime getPasswordLastSet() {
        return this.passwordLastSet;
    }

    @Override
    public String getDisplayName() {
        return this.displayName;
    }

    @Override
    public String getSAMAccountName() {
        return this.sAMAccountName;
    }

    @Override
    public String getUserPrincipalName() {
        return this.userPrincipalName;
    }

    @Override
    public String getMail() {
        return this.mail;
    }

    @Override
    public int getUserAccountControl() {
        return this.userAccountControl;
    }

    // Override standard UserDetails flags to use our AD-specific interpretations if they are more accurate
    // or provide a different meaning.

    @Override
    public boolean isCredentialsNonExpired() {
        // Standard UserDetails flag. We can tie this directly to our AD passwordExpired logic.
        return !this.isPasswordExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        // Standard UserDetails flag. Tied to our AD accountLocked logic.
        return !this.isAccountLocked();
    }

    @Override
    public boolean isAccountNonExpired() {
        // Standard UserDetails flag. Tied to our AD accountExpired logic,
        // which refers to the AD 'accountExpires' attribute, not a UAC flag.
        return !this.isAccountExpired();
    }
}
