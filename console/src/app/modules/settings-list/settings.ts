import { PolicyComponentServiceType } from '../policies/policy-component-types.enum';
import { SidenavSetting } from '../sidenav/sidenav.component';

export const LANGUAGES: SidenavSetting = {
  id: 'languages',
  i18nKey: 'SETTINGS.LIST.LANGUAGES',
  requiredRoles: {
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.read'],
  },
};

export const OIDC: SidenavSetting = {
  id: 'oidc',
  i18nKey: 'SETTINGS.LIST.OIDC',
  requiredRoles: {
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.read'],
  },
};

export const SECRETS: SidenavSetting = {
  id: 'secrets',
  i18nKey: 'SETTINGS.LIST.SECRETS',
  requiredRoles: {
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.read'],
  },
};

export const SECURITY: SidenavSetting = {
  id: 'security',
  i18nKey: 'SETTINGS.LIST.SECURITY',
  requiredRoles: {
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.read'],
  },
};

export const LOGIN: SidenavSetting = {
  id: 'login',
  i18nKey: 'SETTINGS.LIST.LOGIN',
  groupI18nKey: 'SETTINGS.GROUPS.LOGIN',
  requiredRoles: {
    [PolicyComponentServiceType.MGMT]: ['policy.read'],
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.read'],
  },
};

export const VERIFIED_DOMAINS: SidenavSetting = {
  id: 'verified_domains',
  i18nKey: 'SETTINGS.LIST.VERIFIED_DOMAINS',
  groupI18nKey: 'SETTINGS.GROUPS.DOMAIN',
  requiredRoles: {
    [PolicyComponentServiceType.MGMT]: ['org.read'],
  },
};

export const DOMAIN: SidenavSetting = {
  id: 'domain',
  i18nKey: 'SETTINGS.LIST.DOMAIN',
  groupI18nKey: 'SETTINGS.GROUPS.DOMAIN',
  requiredRoles: {
    [PolicyComponentServiceType.MGMT]: ['iam.policy.write'],
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.write'],
  },
};

export const LOCKOUT: SidenavSetting = {
  id: 'lockout',
  i18nKey: 'SETTINGS.LIST.LOCKOUT',
  groupI18nKey: 'SETTINGS.GROUPS.LOGIN',
  requiredRoles: {
    [PolicyComponentServiceType.MGMT]: ['policy.read'],
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.read'],
  },
};

export const COMPLEXITY: SidenavSetting = {
  id: 'complexity',
  i18nKey: 'SETTINGS.LIST.COMPLEXITY',
  groupI18nKey: 'SETTINGS.GROUPS.LOGIN',
  requiredRoles: {
    [PolicyComponentServiceType.MGMT]: ['policy.read'],
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.read'],
  },
};

export const IDP: SidenavSetting = {
  id: 'idp',
  i18nKey: 'SETTINGS.LIST.IDP',
  groupI18nKey: 'SETTINGS.GROUPS.LOGIN',
  requiredRoles: {
    [PolicyComponentServiceType.MGMT]: ['policy.read', 'org.idp.read'],
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.read', 'org.idp.read'],
  },
};

export const NOTIFICATIONS: SidenavSetting = {
  id: 'notifications',
  i18nKey: 'SETTINGS.LIST.NOTIFICATIONS',
  groupI18nKey: 'SETTINGS.GROUPS.NOTIFICATIONS',
  requiredRoles: {
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.read'],
    [PolicyComponentServiceType.MGMT]: ['policy.read'],
  },
};

export const SMTP_PROVIDER: SidenavSetting = {
  id: 'smtpprovider',
  i18nKey: 'SETTINGS.LIST.SMTP_PROVIDER',
  groupI18nKey: 'SETTINGS.GROUPS.NOTIFICATIONS',
  requiredRoles: {
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.read'],
  },
};

export const SMS_PROVIDER: SidenavSetting = {
  id: 'smsprovider',
  i18nKey: 'SETTINGS.LIST.SMS_PROVIDER',
  groupI18nKey: 'SETTINGS.GROUPS.NOTIFICATIONS',
  requiredRoles: {
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.read'],
  },
};

export const MESSAGETEXTS: SidenavSetting = {
  id: 'messagetexts',
  i18nKey: 'SETTINGS.LIST.MESSAGETEXTS',
  groupI18nKey: 'SETTINGS.GROUPS.APPEARANCE',
  requiredRoles: {
    [PolicyComponentServiceType.MGMT]: ['policy.read'],
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.read'],
  },
};

export const LOGINTEXTS: SidenavSetting = {
  id: 'logintexts',
  i18nKey: 'SETTINGS.LIST.LOGINTEXTS',
  groupI18nKey: 'SETTINGS.GROUPS.APPEARANCE',
  requiredRoles: {
    [PolicyComponentServiceType.MGMT]: ['policy.read'],
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.read'],
  },
};

export const PRIVACYPOLICY: SidenavSetting = {
  id: 'privacypolicy',
  i18nKey: 'SETTINGS.LIST.PRIVACYPOLICY',
  groupI18nKey: 'SETTINGS.GROUPS.OTHER',
  requiredRoles: {
    [PolicyComponentServiceType.MGMT]: ['policy.read'],
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.read'],
  },
};

export const BRANDING: SidenavSetting = {
  id: 'branding',
  i18nKey: 'SETTINGS.LIST.BRANDING',
  groupI18nKey: 'SETTINGS.GROUPS.APPEARANCE',
  requiredRoles: {
    [PolicyComponentServiceType.MGMT]: ['policy.read'],
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.read'],
  },
};
