# AzGovViz output reference (v6.x)

Files are written to `<run>/azgovviz/` and named `AzGovViz_<version>_<yyyyMMdd_HHmmss>_<managementGroupId>[_<Suffix>].csv`.
CSV delimiter is `;` (multi-value cells use `, `), every field is quoted, cells may contain newlines - always use a
real CSV parser (`csv.DictReader(..., delimiter=';')`). Values like `True`/`False` and `'true'`/`'false'` both occur.

| Suffix | One row per | Key columns |
|---|---|---|
| *(base)* | scope × policy/role assignment (denormalised, inherited rows repeated) | `level, mgId, mgName, mgParentId, SubscriptionId, Subscription, SubscriptionState, SubscriptionQuotaId, SubscriptionASCSecureScore, SubscriptionTags, Policy*, RoleDefinitionName, RoleAssignmentIdentity*` |
| `RoleAssignments` | role assignment × scope where it applies (inherited rows repeated; `indirect` rows = members of assigned groups) | `RoleAssignmentId, Scope` (`thisScope MG/Sub/Sub RG/Sub RG Res`, `inherited <name>`), `ScopeTenOrMgOrSubOrRGOrRes` (Ten/Mg/Sub/RG/Res = where the assignment was made), `RoleClear` (role name), `RoleId, RoleType` (Builtin/Custom), `AssignmentType` (direct/indirect/nested), `AssignmentInheritFrom, ObjectDisplayName, ObjectSignInName, ObjectId, ObjectType` (`User Member`, `User Guest`, `Group`, `SP APP INT/EXT`, `SP MI Sys/Usr`, `Unknown` = orphaned), `RoleAssignmentPIMRelated, RoleAssignmentPIMAssignmentType, RbacRelatedPolicyAssignmentClear, RoleSecurityCustomRoleOwner, RoleSecurityOwnerAssignmentSP, RoleCanDoRoleAssignments, CreatedOn, CreatedBy, MgId, SubscriptionId, SubscriptionName` |
| `RoleDefinitions` | role definition | `Name, Id, Type, AssignmentsCount, AssignableScopes, RoleAssWriteCapable, Actions, NotActions, DataActions` |
| `ClassicAdministrators` | classic admin | `Subscription, SubscriptionId, Identity, Role` |
| `PIMEligibility` | PIM-eligible assignment (service principal runs only) | `Scope, ScopeName, Role, IdentityDisplayName, IdentityType, PIMEligibilityStartDateTime, PIMEligibilityEndDateTime` |
| `PolicyAssignments` | policy assignment × scope where it applies | `PolicyAssignmentId, PolicyAssignmentDisplayName, PolicyAssignmentScopeName, PolicyAssignmentEnforcementMode` (Default/DoNotEnforce), `Inheritance` (`thisScope Mg/Sub/Sub RG`, `inherited …`), `Effect, PolicyNameClear, PolicyId, PolicyVariant, PolicyType` (BuiltIn/Custom/Static), `PolicyIsALZ, PolicyCategory, PolicyAvailability` (`na` = definition missing), `NonCompliantResources, CompliantResources, ExcludedScope, ExemptionScope, PolicyAssignmentMI, subscriptionId, MgId` |
| `PolicyDefinitions` / `PolicySetDefinitions` | definition | `Type, Scope, PolicyDisplayName/PolicySetDisplayName, UniqueAssignmentsCount, UsedInPolicySetsCount, PolicyEffect, ALZ, ALZState` |
| `PolicyExemptions` | exemption | `Scope, ExemptionName, Category, ExpiresOn_UTC` (date / `expired …` / `n/a`), `PolicyAssignmentId, Policy` |
| `PolicyRemediation` | non-compliant DINE/Modify policy | `policyAssignmentDisplayName, policyDefinitionDisplayName, effect, nonCompliantResourcesCount` |
| `PolicyCustomBuiltInParity` | custom policy identical to a built-in | `CustomPolicyDisplayName, BuiltInPolicyId` |
| `ALZPolicyVersionChecker` | ALZ policy | `PolicyName, PolicyScope, ALZState` (upToDate/outDated/deprecated/obsolete), `InTenant, AzAdvertizerUrl` |
| `SubscriptionDetails` | subscription | `Subscription, SubscriptionId, QuotaId, ManagementGroupPath, Tags, Owner(atScope)Direct, Owner(atScope)Indirect, UserAccessAdministrator(atScope)Direct, MDfCScore, MDfCEmailNotifications*`, Advisor scores |
| `MDfCCoverage` | Defender plan × subscription | `plan, subscriptionId, subscriptionName, pricingTier` (Free/Standard), `<Plan>_subPlan`, `<Plan>_ext_*` |
| `MDfCEmailNotifications` | subscription | `alertNotificationsState, alertNotificationsminimalSeverity, roles, emails` |
| `ResourcesAll` | resource | `subscriptionId, subscriptionName, mgPath, type, sku_*, kind, id, name, location, tags, createdTime, cafResourceNamingResult` (passed/failed/n/a) |
| `ResourceLocks` | lock | `SubscriptionName, ScopeType, Lock` (CannotDelete/ReadOnly), `Id` |
| `ResourcesCostOptimizationAndCleanup` | orphaned/idle resource | `type, subscriptionId, Resource, Intent` (`cost savings`, `misconfiguration`, `clean up`, `cost savings - stopped but not deallocated VM`), `Cost, Currency` with consumption |
| `StorageAccountAccessAnalysis` | storage account | `storageAccount, allowBlobPublicAccess, publicNetworkAccess, networkAclsdefaultAction, containersAnonymousContainerCount, containersAnonymousBlobCount, staticWebsitesState, supportsHttpsTrafficOnly, minimumTlsVersion, allowSharedKeyAccess` |
| `VirtualNetworks` | VNet | `VNet, SubscriptionName, AddressSpaceAddressPrefixes, SubnetsCount, SubnetsWithNSGCount, PrivateEndpointsCount, DdosProtection, PeeringsCount` |
| `VirtualNetworkSubnets` | subnet | `SubnetName, VNet, SubnetPrefix, AvailableIPAddresses, UsedIPAddressesPercent, SubnetIPAddressUsageCritical, NetworkSecurityGroup, RouteTable, Delegation` |
| `VirtualNetworkPeerings` | peering | `VNet, PeeringName, PeeringState, AllowForwardedTraffic, UseRemoteGateways, RemoteVNet, RemoteSubscriptionName, PeeringXTenant` |
| `PrivateEndpoints` | private endpoint | `PEName, PESubscriptionName, Resource, ResourceType, CrossSubscriptionPE, CrossTenantPE, SubnetVNet` |
| `AdvisorScores` | subscription × category | `subscriptionName, category, score` |
| `Consumption` | cost line (`--consumption`) | `PreTaxCost, Currency, SubscriptionName, ResourceType, MeterCategory` |
| `DailySummary` | metric | `capability, count` (e.g. `ManagementGroups`, `Subscriptions`, `PolicyAssignments`, `TotalRoleAssignments`, `RoleDefinitionsCustom`, `Resources`) |
| `ResourceProviders`, `SubscriptionsFeatures`, `UserAssignedIdentities4Resources`, `ResourceFluctuation*` | see file header | |

Other outputs: `AzGovViz_*.html` (interactive report, opens offline only partially - it loads JS/CSS from CDNs),
`AzGovViz_*_DefinitionInsights.html`, `AzGovViz_*.md` (Mermaid hierarchy), `JSON_<mg>_<timestamp>/` (full
hierarchy with every policy/role assignment and definition as JSON), `*_PolicyAll.json`, and the console log
`azgovviz-console.log` (contains the "LEAST PRIVILEGE ADVICE" when the identity holds more than Reader).

Counting tips:
- Unique role assignments: de-duplicate on `RoleAssignmentId` among `AssignmentType == direct` rows.
- Effective Owners of a subscription: rows with that `SubscriptionId`, `RoleClear == Owner`, `AssignmentType == direct`
  and `Scope` = `thisScope Sub` or `inherited …`.
- Unique policy assignments: de-duplicate on `PolicyAssignmentId`; the assignment's own scope is the row whose
  `Inheritance` starts with `thisScope`.
