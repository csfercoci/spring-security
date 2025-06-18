package org.springframework.security.ldap.authentication.ad;

import org.springframework.util.Assert;

public class ActiveDirectoryLdapProperties {

    private String domain;
    private String url;
    private String rolePrefix = "ROLE_"; // Default role prefix
    private String userSearchBase = ""; // Default to empty, meaning search from root or as per AD default
    private String userSearchFilter = "(&(objectClass=user)(sAMAccountName={0}))"; // Common AD user search filter
    private String groupRoleAttribute = "cn"; // Typically 'cn' for group name from 'memberOf' attribute
    private String memberOfAttribute = "memberOf"; // Standard AD attribute for group membership listings

    // It's good practice to provide a constructor, even if it's just a default one,
    // or one that initializes mandatory fields.
    // For this class, we might expect url to be mandatory. Domain can be optional.

    public ActiveDirectoryLdapProperties() {
    }

    // Getters and Setters for each property

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        Assert.hasText(url, "LDAP URL must not be empty or null");
        this.url = url;
    }

    public String getRolePrefix() {
        return rolePrefix;
    }

    public void setRolePrefix(String rolePrefix) {
        Assert.notNull(rolePrefix, "Role prefix must not be null");
        this.rolePrefix = rolePrefix;
    }

    public String getUserSearchBase() {
        return userSearchBase;
    }

    public void setUserSearchBase(String userSearchBase) {
        Assert.notNull(userSearchBase, "User search base must not be null (can be empty string)");
        this.userSearchBase = userSearchBase;
    }

    public String getUserSearchFilter() {
        return userSearchFilter;
    }

    public void setUserSearchFilter(String userSearchFilter) {
        Assert.hasText(userSearchFilter, "User search filter must not be empty or null");
        this.userSearchFilter = userSearchFilter;
    }

    public String getGroupRoleAttribute() {
        return groupRoleAttribute;
    }

    public void setGroupRoleAttribute(String groupRoleAttribute) {
        Assert.hasText(groupRoleAttribute, "Group role attribute must not be empty or null");
        this.groupRoleAttribute = groupRoleAttribute;
    }

    public String getMemberOfAttribute() {
        return memberOfAttribute;
    }

    public void setMemberOfAttribute(String memberOfAttribute) {
        Assert.hasText(memberOfAttribute, "MemberOf attribute must not be empty or null");
        this.memberOfAttribute = memberOfAttribute;
    }
}
