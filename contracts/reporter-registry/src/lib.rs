//! Reporter registry: decides which addresses may post reserve reports and
//! supply snapshots to the coverage ledger, and in which role.
#![no_std]

use plimsoll_types::{
    PendingUpgrade, RegistryRole, ReporterInfo, Role, INSTANCE_EXTEND_TO, INSTANCE_THRESHOLD,
    PERSISTENT_EXTEND_TO, PERSISTENT_THRESHOLD, UPGRADE_DELAY_LEDGERS,
};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address,
    BytesN, ContractExecutable, Env, String,
};

const MAX_NAME_LEN: u32 = 64;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Reporter(Address),
    PendingUpgrade,
    /// Explicit access tier assigned to an address via `assign_role`.
    AccessRole(Address),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RegistryError {
    ReporterNotFound = 1,
    InvalidName = 2,
    UpgradeNotProposed = 3,
    UpgradeDelayNotElapsed = 4,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReporterSet {
    #[topic]
    pub reporter: Address,
    pub role: Role,
    pub name: String,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReporterRevoked {
    #[topic]
    pub reporter: Address,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferred {
    #[topic]
    pub new_admin: Address,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeProposed {
    #[topic]
    pub wasm_hash: BytesN<32>,
    pub executable_at_ledger: u32,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeExecuted {
    #[topic]
    pub wasm_hash: BytesN<32>,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeCancelled {
    #[topic]
    pub wasm_hash: BytesN<32>,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleAssigned {
    #[topic]
    pub assignee: Address,
    pub tier: RegistryRole,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleRevoked {
    #[topic]
    pub assignee: Address,
}

#[contract]
pub struct ReporterRegistry;

fn admin(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::Admin)
        .expect("admin is set in the constructor")
}

fn bump_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_THRESHOLD, INSTANCE_EXTEND_TO);
}

fn pending(env: &Env) -> Option<PendingUpgrade> {
    env.storage().instance().get(&DataKey::PendingUpgrade)
}

#[contractimpl]
impl ReporterRegistry {
    /// Initialises the registry with `admin` as the sole administrator.
    ///
    /// # Arguments
    /// * `admin` - the address that will control this contract
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        bump_instance(&env);
    }

    /// Returns the current administrator address.
    pub fn admin(env: Env) -> Address {
        admin(&env)
    }

    /// Add a reporter, or change an existing reporter's role and name.
    ///
    /// If `reporter` already exists, `added_at` is preserved; otherwise it is
    /// set to the current ledger timestamp.
    ///
    /// # Arguments
    /// * `reporter` - the address being registered or updated
    /// * `role` - `Auditor`, `Transcriber`, or `SupplyPoster`
    /// * `name` - display name, 1–64 bytes
    ///
    /// # Errors
    /// * [`RegistryError::InvalidName`] when `name` is empty or longer than 64 bytes
    ///
    /// # Events
    /// * [`ReporterSet`] on success
    pub fn set_reporter(env: Env, reporter: Address, role: Role, name: String) {
        admin(&env).require_auth();
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            panic_with_error!(&env, RegistryError::InvalidName);
        }
        let key = DataKey::Reporter(reporter.clone());
        let added_at = env
            .storage()
            .persistent()
            .get::<_, ReporterInfo>(&key)
            .map(|existing| existing.added_at)
            .unwrap_or_else(|| env.ledger().timestamp());
        let info = ReporterInfo {
            role,
            name: name.clone(),
            added_at,
        };
        env.storage().persistent().set(&key, &info);
        env.storage()
            .persistent()
            .extend_ttl(&key, PERSISTENT_THRESHOLD, PERSISTENT_EXTEND_TO);
        bump_instance(&env);
        ReporterSet {
            reporter,
            role,
            name,
        }
        .publish(&env);
    }

    /// Remove a reporter from the registry.
    ///
    /// # Arguments
    /// * `reporter` - the address to revoke
    ///
    /// # Errors
    /// * [`RegistryError::ReporterNotFound`] when `reporter` is not registered
    ///
    /// # Events
    /// * [`ReporterRevoked`] on success
    pub fn revoke(env: Env, reporter: Address) {
        admin(&env).require_auth();
        let key = DataKey::Reporter(reporter.clone());
        if !env.storage().persistent().has(&key) {
            panic_with_error!(&env, RegistryError::ReporterNotFound);
        }
        env.storage().persistent().remove(&key);
        bump_instance(&env);
        ReporterRevoked { reporter }.publish(&env);
    }

    /// Return the role of `reporter`, or `None` if not registered.
    ///
    /// # Arguments
    /// * `reporter` - the address to query
    pub fn role_of(env: Env, reporter: Address) -> Option<Role> {
        Self::get_reporter(env, reporter).map(|info| info.role)
    }

    /// Return the full reporter record for `reporter`, or `None` if not registered.
    ///
    /// # Arguments
    /// * `reporter` - the address to query
    pub fn get_reporter(env: Env, reporter: Address) -> Option<ReporterInfo> {
        let key = DataKey::Reporter(reporter);
        let info = env.storage().persistent().get::<_, ReporterInfo>(&key);
        if info.is_some() {
            env.storage()
                .persistent()
                .extend_ttl(&key, PERSISTENT_THRESHOLD, PERSISTENT_EXTEND_TO);
        }
        info
    }

    /// Transfer admin rights to `new_admin`. Requires both current and new
    /// admin to authorise.
    ///
    /// # Arguments
    /// * `new_admin` - the address that will become administrator
    ///
    /// # Events
    /// * [`AdminTransferred`] on success
    pub fn transfer_admin(env: Env, new_admin: Address) {
        admin(&env).require_auth();
        new_admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        bump_instance(&env);
        AdminTransferred { new_admin }.publish(&env);
    }

    /// Propose a wasm hash for installation after the upgrade delay. A new
    /// proposal replaces any pending one and restarts the clock.
    ///
    /// # Arguments
    /// * `wasm_hash` - hash of the new wasm to install
    ///
    /// # Events
    /// * [`UpgradeProposed`] on success
    pub fn propose_upgrade(env: Env, wasm_hash: BytesN<32>) {
        admin(&env).require_auth();
        let executable_at_ledger = env
            .ledger()
            .sequence()
            .saturating_add(UPGRADE_DELAY_LEDGERS);
        env.storage().instance().set(
            &DataKey::PendingUpgrade,
            &PendingUpgrade {
                wasm_hash: wasm_hash.clone(),
                executable_at_ledger,
            },
        );
        bump_instance(&env);
        UpgradeProposed {
            wasm_hash,
            executable_at_ledger,
        }
        .publish(&env);
    }

    /// Install the pending wasm once its delay has elapsed.
    ///
    /// # Errors
    /// * [`RegistryError::UpgradeNotProposed`] when no upgrade has been proposed
    /// * [`RegistryError::UpgradeDelayNotElapsed`] when the delay has not yet passed
    ///
    /// # Events
    /// * [`UpgradeExecuted`] on success
    pub fn execute_upgrade(env: Env) {
        admin(&env).require_auth();
        let proposed = match pending(&env) {
            Some(proposed) => proposed,
            None => panic_with_error!(&env, RegistryError::UpgradeNotProposed),
        };
        if env.ledger().sequence() < proposed.executable_at_ledger {
            panic_with_error!(&env, RegistryError::UpgradeDelayNotElapsed);
        }
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        bump_instance(&env);
        UpgradeExecuted {
            wasm_hash: proposed.wasm_hash.clone(),
        }
        .publish(&env);
        env.deployer()
            .update_current_contract(ContractExecutable::Wasm(proposed.wasm_hash));
    }

    /// Cancel the pending upgrade.
    ///
    /// # Errors
    /// * [`RegistryError::UpgradeNotProposed`] when no upgrade has been proposed
    ///
    /// # Events
    /// * [`UpgradeCancelled`] on success
    pub fn cancel_upgrade(env: Env) {
        admin(&env).require_auth();
        let proposed = match pending(&env) {
            Some(proposed) => proposed,
            None => panic_with_error!(&env, RegistryError::UpgradeNotProposed),
        };
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        bump_instance(&env);
        UpgradeCancelled {
            wasm_hash: proposed.wasm_hash,
        }
        .publish(&env);
    }

    /// Return the pending upgrade, if any.
    pub fn pending_upgrade(env: Env) -> Option<PendingUpgrade> {
        let proposed = pending(&env);
        if proposed.is_some() {
            bump_instance(&env);
        }
        proposed
    }

    /// Assign an explicit access tier to `assignee`. Requires admin auth.
    ///
    /// An explicit tier overrides the implicit `Reporter` tier that any address
    /// registered via `set_reporter` would otherwise have. Existing reporter
    /// records are unaffected.
    ///
    /// # Arguments
    /// * `assignee` - the address receiving the tier
    /// * `tier` - the `RegistryRole` tier to assign
    ///
    /// # Events
    /// * [`RoleAssigned`] on success
    pub fn assign_role(env: Env, assignee: Address, tier: RegistryRole) {
        admin(&env).require_auth();
        let key = DataKey::AccessRole(assignee.clone());
        env.storage().persistent().set(&key, &tier);
        env.storage()
            .persistent()
            .extend_ttl(&key, PERSISTENT_THRESHOLD, PERSISTENT_EXTEND_TO);
        bump_instance(&env);
        RoleAssigned { assignee, tier }.publish(&env);
    }

    /// Remove the explicit access tier of `assignee`. Requires admin auth.
    ///
    /// If `assignee` is also a registered reporter, they revert to the implicit
    /// `Reporter` tier returned by `access_tier`. If not registered, their tier
    /// becomes `None`.
    ///
    /// This is a no-op when `assignee` has no explicit tier.
    ///
    /// # Arguments
    /// * `assignee` - the address whose explicit tier is removed
    ///
    /// # Events
    /// * [`RoleRevoked`] on success
    pub fn revoke_role(env: Env, assignee: Address) {
        admin(&env).require_auth();
        env.storage()
            .persistent()
            .remove(&DataKey::AccessRole(assignee.clone()));
        bump_instance(&env);
        RoleRevoked { assignee }.publish(&env);
    }

    /// Return the access tier of `address`.
    ///
    /// An explicit tier set via `assign_role` takes precedence. If none is set,
    /// any address registered via `set_reporter` is treated as `Reporter` tier.
    /// Returns `None` for addresses with neither.
    ///
    /// # Arguments
    /// * `address` - the address to query
    pub fn access_tier(env: Env, address: Address) -> Option<RegistryRole> {
        let key = DataKey::AccessRole(address.clone());
        if let Some(tier) = env
            .storage()
            .persistent()
            .get::<_, RegistryRole>(&key)
        {
            env.storage()
                .persistent()
                .extend_ttl(&key, PERSISTENT_THRESHOLD, PERSISTENT_EXTEND_TO);
            return Some(tier);
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::Reporter(address))
        {
            return Some(RegistryRole::Reporter);
        }
        None
    }
}

#[cfg(test)]
mod test;
