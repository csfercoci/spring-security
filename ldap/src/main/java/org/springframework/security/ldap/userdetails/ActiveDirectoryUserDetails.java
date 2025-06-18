package org.springframework.security.ldap.userdetails;

import java.time.LocalDateTime; // Or long for Windows File Time

public interface ActiveDirectoryUserDetails extends LdapUserDetails {

    // Methods for account status flags (derived from userAccountControl)
    boolean isAccountLocked();
    boolean isAccountDisabled(); // Note: LdapUserDetails already has isEnabled(), this is specific
    boolean isAccountExpired(); // AD specific account expiry, not password
    boolean isPasswordExpired(); // Typically true if pwdLastSet is 0 or user must change password
    boolean isPasswordNeverExpires(); // From userAccountControl DONT_EXPIRE_PASSWD flag

    // Methods for password information
    LocalDateTime getPasswordLastSet(); // From pwdLastSet attribute (converted from Windows File Time)
    // long getTimeUntilPasswordExpiry(); // Could be derived if domain policy is known

    // Common AD user attributes
    String getDisplayName(); // From displayName attribute
    String getSAMAccountName(); // From sAMAccountName attribute
    String getUserPrincipalName(); // From userPrincipalName attribute
    String getMail(); // From mail attribute

    // Raw userAccountControl value might also be useful
    int getUserAccountControl();
}
