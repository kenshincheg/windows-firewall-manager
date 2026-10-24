//! Работа с Windows Firewall через COM (`INetFwPolicy2`).

mod duplicates;
pub use duplicates::remove_rule_snapshot;

use crate::model::{Action, Direction, FirewallRule, Profiles, Protocol, validate_rule};
use windows::Win32::Foundation::{VARIANT_BOOL, VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NET_FW_ACTION, NET_FW_ACTION_ALLOW,
    NET_FW_ACTION_BLOCK, NET_FW_IP_PROTOCOL_ANY, NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP,
    NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT, NET_FW_RULE_DIRECTION, NetFwPolicy2, NetFwRule,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoUninitialize, IDispatch,
};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::{VARIANT, VT_DISPATCH, VT_UNKNOWN, VariantClear};
use windows::core::{BSTR, IUnknown, Interface};

struct ComGuard {
    should_uninit: bool,
}

impl ComGuard {
    fn new() -> Result<Self, String> {
        unsafe {
            let hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            // S_OK (0) или S_FALSE (1) — ок; RPC_E_CHANGED_MODE — другой поток уже инициализирован иначе.
            if hr.is_ok() {
                return Ok(Self {
                    should_uninit: true,
                });
            }
            if hr.0 == 0x8001_0106u32 as i32 {
                // Уже другой режим COM — пробуем работать без Uninitialize.
                return Ok(Self {
                    should_uninit: false,
                });
            }
            Err(map_hresult(hr, "CoInitializeEx"))
        }
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.should_uninit {
            unsafe { CoUninitialize() };
        }
    }
}

fn map_hresult(hr: windows::core::HRESULT, ctx: &str) -> String {
    map_com_err(windows::core::Error::from(hr), ctx)
}

fn map_com_err(e: windows::core::Error, ctx: &str) -> String {
    let code = e.code().0 as u32;
    let msg = if code == 0x8007_0005 {
        format!("{ctx}: отказано в доступе. Запустите от имени администратора.")
    } else {
        format!("{ctx}: ошибка Firewall API (0x{code:08X}): {e}")
    };
    crate::logutil::error(&msg);
    msg
}

fn policy() -> Result<INetFwPolicy2, String> {
    unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| map_com_err(e, "NetFwPolicy2"))
}

fn new_rule() -> Result<INetFwRule, String> {
    unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| map_com_err(e, "NetFwRule"))
}

fn direction_to_fw(d: Direction) -> NET_FW_RULE_DIRECTION {
    match d {
        Direction::Inbound => NET_FW_RULE_DIR_IN,
        Direction::Outbound => NET_FW_RULE_DIR_OUT,
    }
}

fn direction_from_fw(d: NET_FW_RULE_DIRECTION) -> Direction {
    if d == NET_FW_RULE_DIR_OUT {
        Direction::Outbound
    } else {
        Direction::Inbound
    }
}

fn action_to_fw(a: Action) -> NET_FW_ACTION {
    match a {
        Action::Allow => NET_FW_ACTION_ALLOW,
        Action::Block => NET_FW_ACTION_BLOCK,
    }
}

fn action_from_fw(a: NET_FW_ACTION) -> Action {
    if a == NET_FW_ACTION_BLOCK {
        Action::Block
    } else {
        Action::Allow
    }
}

fn protocol_to_fw(p: Protocol) -> i32 {
    match p {
        Protocol::Tcp => NET_FW_IP_PROTOCOL_TCP.0,
        Protocol::Udp => NET_FW_IP_PROTOCOL_UDP.0,
        Protocol::Any => NET_FW_IP_PROTOCOL_ANY.0,
        Protocol::Other(value) => value,
    }
}

fn protocol_from_fw(p: i32) -> Protocol {
    match p {
        x if x == NET_FW_IP_PROTOCOL_TCP.0 => Protocol::Tcp,
        x if x == NET_FW_IP_PROTOCOL_UDP.0 => Protocol::Udp,
        x if x == NET_FW_IP_PROTOCOL_ANY.0 => Protocol::Any,
        x => Protocol::Other(x),
    }
}

fn bool_to_variant(v: bool) -> VARIANT_BOOL {
    if v { VARIANT_TRUE } else { VARIANT_FALSE }
}

fn variant_to_bool(v: VARIANT_BOOL) -> bool {
    v.0 != 0
}

fn rule_from_com(fw: &INetFwRule) -> Result<FirewallRule, String> {
    unsafe {
        let name = fw.Name().map_err(|e| map_com_err(e, "Name"))?.to_string();
        let direction = direction_from_fw(fw.Direction().map_err(|e| map_com_err(e, "Direction"))?);
        let action = action_from_fw(fw.Action().map_err(|e| map_com_err(e, "Action"))?);
        let protocol = protocol_from_fw(fw.Protocol().map_err(|e| map_com_err(e, "Protocol"))?);
        let local_ports = fw.LocalPorts().map(|b| b.to_string()).unwrap_or_default();
        let application_path = fw
            .ApplicationName()
            .map(|b| b.to_string())
            .unwrap_or_default();
        let profiles =
            Profiles::from_bitmask(fw.Profiles().map_err(|e| map_com_err(e, "Profiles"))?);
        let enabled = variant_to_bool(fw.Enabled().map_err(|e| map_com_err(e, "Enabled"))?);
        let description = fw.Description().map(|b| b.to_string()).unwrap_or_default();
        Ok(FirewallRule {
            name,
            direction,
            action,
            protocol,
            local_ports,
            application_path,
            profiles,
            enabled,
            description,
            comparison_key: duplicates::comparison_key(fw).ok(),
        })
    }
}

/// Список всех правил WFAS.
pub fn list_rules() -> Result<Vec<FirewallRule>, String> {
    let _com = ComGuard::new()?;
    let policy = policy()?;
    let rules: INetFwRules = unsafe { policy.Rules() }.map_err(|e| map_com_err(e, "Rules"))?;
    collect_com_rules(&rules)?
        .iter()
        .map(rule_from_com)
        .collect()
}

fn collect_com_rules(rules: &INetFwRules) -> Result<Vec<INetFwRule>, String> {
    let count = unsafe { rules.Count() }.map_err(|e| map_com_err(e, "Count"))?;
    let mut out = Vec::with_capacity(count.max(0) as usize);

    let unknown: IUnknown = unsafe { rules._NewEnum() }.map_err(|e| map_com_err(e, "_NewEnum"))?;
    let enumerator: IEnumVARIANT = unknown.cast().map_err(|e| map_com_err(e, "IEnumVARIANT"))?;

    loop {
        let mut vars = [VARIANT::default()];
        let mut fetched = 0u32;
        let hr = unsafe { enumerator.Next(&mut vars, &mut fetched) };
        if hr.is_err() {
            unsafe {
                let _ = VariantClear(&mut vars[0]);
            }
            return Err(map_hresult(hr, "Перечисление правил"));
        }
        if fetched == 0 {
            break;
        }

        let parsed = unsafe { variant_to_rule(&vars[0]) };
        unsafe {
            let _ = VariantClear(&mut vars[0]);
        }
        out.push(parsed?);
    }

    Ok(out)
}

unsafe fn variant_to_rule(var: &VARIANT) -> Result<INetFwRule, String> {
    let vt = unsafe { var.Anonymous.Anonymous.vt };
    let unknown: IUnknown = if vt == VT_DISPATCH {
        let disp: Option<IDispatch> =
            unsafe { (*var.Anonymous.Anonymous.Anonymous.pdispVal).clone() };
        let disp = disp.ok_or_else(|| "пустой IDispatch".to_string())?;
        disp.cast()
            .map_err(|e| map_com_err(e, "IDispatch→IUnknown"))?
    } else if vt == VT_UNKNOWN {
        let unk: Option<IUnknown> = unsafe { (*var.Anonymous.Anonymous.Anonymous.punkVal).clone() };
        unk.ok_or_else(|| "пустой IUnknown".to_string())?
    } else {
        let code = vt.0;
        return Err(format!("неожиданный VT={code}"));
    };

    unknown.cast().map_err(|e| map_com_err(e, "INetFwRule"))
}

fn apply_rule_props(fw: &INetFwRule, rule: &FirewallRule, set_name: bool) -> Result<(), String> {
    validate_rule(rule)?;
    unsafe {
        if set_name {
            fw.SetName(&BSTR::from(rule.name.trim()))
                .map_err(|e| map_com_err(e, "SetName"))?;
        }
        let old_protocol = fw.Protocol().map_err(|e| map_com_err(e, "Protocol"))?;
        if matches!(old_protocol, 6 | 17) && rule.protocol == Protocol::Any {
            let remote = fw
                .RemotePorts()
                .map_err(|e| map_com_err(e, "RemotePorts"))?
                .to_string();
            if !remote.is_empty() && remote != "*" {
                return Err("Нельзя выбрать «Любой»: правило ограничивает удалённые порты. Измените его в расширенных настройках Windows".into());
            }
            fw.SetLocalPorts(&BSTR::from("*"))
                .map_err(|e| map_com_err(e, "Сброс локальных портов"))?;
            fw.SetRemotePorts(&BSTR::from("*"))
                .map_err(|e| map_com_err(e, "Сброс удалённых портов"))?;
        }
        fw.SetDirection(direction_to_fw(rule.direction))
            .map_err(|e| map_com_err(e, "SetDirection"))?;
        fw.SetAction(action_to_fw(rule.action))
            .map_err(|e| map_com_err(e, "SetAction"))?;
        fw.SetProtocol(protocol_to_fw(rule.protocol))
            .map_err(|e| map_com_err(e, "SetProtocol"))?;
        fw.SetProfiles(rule.profiles.as_bitmask())
            .map_err(|e| map_com_err(e, "SetProfiles"))?;
        fw.SetDescription(&BSTR::from(rule.description.trim()))
            .map_err(|e| map_com_err(e, "SetDescription"))?;
        if matches!(rule.protocol, Protocol::Tcp | Protocol::Udp) {
            let ports = rule.local_ports.trim();
            fw.SetLocalPorts(&BSTR::from(if ports.is_empty() { "*" } else { ports }))
                .map_err(|e| map_com_err(e, "SetLocalPorts"))?;
        }
        fw.SetApplicationName(&BSTR::from(rule.application_path.trim()))
            .map_err(|e| map_com_err(e, "SetApplicationName"))?;
        fw.SetEnabled(bool_to_variant(rule.enabled))
            .map_err(|e| map_com_err(e, "SetEnabled"))?;
    }
    Ok(())
}

/// Добавить правило.
pub fn add_rule(rule: &FirewallRule) -> Result<(), String> {
    let _com = ComGuard::new()?;
    let policy = policy()?;
    let rules: INetFwRules = unsafe { policy.Rules() }.map_err(|e| map_com_err(e, "Rules"))?;
    let fw = new_rule()?;
    apply_rule_props(&fw, rule, true)?;
    unsafe { rules.Add(&fw) }.map_err(|e| map_com_err(e, "Add"))?;
    Ok(())
}

/// Update the existing COM object; rename last, without deleting the original rule.
pub fn update_rule(original_name: &str, rule: &FirewallRule) -> Result<(), String> {
    let original = original_name.trim();
    let new_name = rule.name.trim();
    if original.is_empty() {
        return Err("Исходное имя правила пустое".into());
    }
    if new_name.is_empty() {
        return Err("Новое имя правила пустое".into());
    }

    validate_rule(rule)?;

    let _com = ComGuard::new()?;
    let policy = policy()?;
    let rules: INetFwRules = unsafe { policy.Rules() }.map_err(|e| map_com_err(e, "Rules"))?;
    let matching: Vec<_> = collect_com_rules(&rules)?
        .into_iter()
        .filter(|fw| {
            unsafe { fw.Name() }
                .ok()
                .is_some_and(|name| name == original)
        })
        .collect();
    if matching.len() != 1 {
        return Err(
            "Имя не определяет одно правило. Выберите нужную строку в обновлённом списке".into(),
        );
    }
    let fw = &matching[0];
    update_existing_rule(fw, original, rule)
}

/// Редактировать именно выбранную копию; устаревший снимок не применяется.
pub fn update_rule_snapshot(original: &FirewallRule, rule: &FirewallRule) -> Result<(), String> {
    validate_rule(rule)?;
    let _com = ComGuard::new()?;
    let policy = policy()?;
    let rules = unsafe { policy.Rules() }.map_err(|e| map_com_err(e, "Rules"))?;
    let fw = duplicates::find_snapshot_rule(&rules, original)?;
    if matches!(
        unsafe { fw.Protocol() }.map_err(|e| map_com_err(e, "Protocol"))?,
        6 | 17 | 256
    ) {
        update_existing_rule(&fw, &original.name, rule)
    } else {
        Err("Этот протокол пока нельзя редактировать в форме программы".into())
    }
}

/// Name stays unchanged if validation or another property update fails.
/// Properties of this COM object commit individually, so this is not a transaction.
fn update_existing_rule(
    fw: &INetFwRule,
    original: &str,
    rule: &FirewallRule,
) -> Result<(), String> {
    // Проверить все поля и COM-ограничения на отсоединённом объекте до изменения политики.
    apply_rule_props(&new_rule()?, rule, true)?;
    apply_rule_props(fw, rule, false)?;
    if original != rule.name.trim() {
        unsafe { fw.SetName(&BSTR::from(rule.name.trim())) }
            .map_err(|e| map_com_err(e, "SetName"))?;
    }
    Ok(())
}

/// Удалить правило по имени.
pub fn remove_rule(name: &str) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Имя правила пустое".into());
    }
    let _com = ComGuard::new()?;
    let policy = policy()?;
    let rules: INetFwRules = unsafe { policy.Rules() }.map_err(|e| map_com_err(e, "Rules"))?;
    unsafe { rules.Remove(&BSTR::from(name)) }.map_err(|e| map_com_err(e, "Remove"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switching_to_any_does_not_drop_hidden_remote_port_restrictions() {
        let _com = ComGuard::new().unwrap();
        let fw = new_rule().unwrap();
        let original = FirewallRule {
            name: "Restricted".into(),
            local_ports: "22".into(),
            enabled: false,
            ..Default::default()
        };
        apply_rule_props(&fw, &original, true).unwrap();
        unsafe {
            fw.SetRemotePorts(&BSTR::from("443")).unwrap();
        }
        let before = rule_from_com(&fw).unwrap();
        let requested = FirewallRule {
            protocol: Protocol::Any,
            local_ports: String::new(),
            application_path: std::env::current_exe().unwrap().display().to_string(),
            ..original
        };
        assert!(update_existing_rule(&fw, "Restricted", &requested).is_err());
        assert_eq!(rule_from_com(&fw).unwrap(), before);
    }

    #[test]
    fn reading_icmp_preserves_the_native_protocol() {
        let _com = ComGuard::new().unwrap();
        let fw = new_rule().unwrap();
        unsafe {
            fw.SetProtocol(1).unwrap();
        }
        assert_eq!(rule_from_com(&fw).unwrap().protocol, Protocol::Other(1));
    }

    #[test]
    fn editing_profiles_application_and_enabled_preserves_advanced_scope() {
        let _com = ComGuard::new().unwrap();
        let fw = new_rule().unwrap();
        let original = FirewallRule {
            name: "Original".into(),
            local_ports: "22".into(),
            enabled: false,
            application_path: std::env::current_exe().unwrap().display().to_string(),
            profiles: Profiles {
                domain: false,
                private: true,
                public: false,
            },
            ..Default::default()
        };
        apply_rule_props(&fw, &original, true).unwrap();
        unsafe {
            fw.SetRemoteAddresses(&BSTR::from("192.0.2.0/24")).unwrap();
            fw.SetGrouping(&BSTR::from("Keep group")).unwrap();
        }
        let remote = unsafe { fw.RemoteAddresses() }.unwrap();
        let application = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/cmd.exe");
        let changed = FirewallRule {
            name: "Renamed".into(),
            local_ports: "80,443".into(),
            application_path: application.display().to_string(),
            enabled: true,
            protocol: Protocol::Udp,
            direction: Direction::Outbound,
            action: Action::Block,
            profiles: Profiles {
                domain: true,
                private: false,
                public: true,
            },
            ..original
        };
        update_existing_rule(&fw, "Original", &changed).unwrap();
        let saved = rule_from_com(&fw).unwrap();
        assert_eq!(saved.profiles, changed.profiles);
        assert_eq!(saved.protocol, Protocol::Udp);
        assert_eq!(saved.direction, Direction::Outbound);
        assert_eq!(saved.action, Action::Block);
        assert!(saved.enabled);
        assert!(
            saved
                .application_path
                .eq_ignore_ascii_case(&changed.application_path)
        );
        assert_eq!(unsafe { fw.RemoteAddresses() }.unwrap(), remote);
        assert_eq!(unsafe { fw.Grouping() }.unwrap(), "Keep group");
    }

    #[test]
    fn any_protocol_application_rule_can_be_created() {
        let _com = ComGuard::new().unwrap();
        let fw = new_rule().unwrap();
        let rule = FirewallRule {
            name: "Any application".into(),
            protocol: Protocol::Any,
            enabled: false,
            application_path: std::env::current_exe().unwrap().display().to_string(),
            ..Default::default()
        };
        apply_rule_props(&fw, &rule, true).unwrap();
        assert_eq!(unsafe { fw.Protocol() }.unwrap(), 256);
    }

    #[test]
    fn invalid_ports_do_not_partially_change_existing_properties() {
        let _com = ComGuard::new().unwrap();
        let fw = new_rule().unwrap();
        unsafe {
            fw.SetName(&BSTR::from("Original")).unwrap();
            fw.SetDescription(&BSTR::from("Original description"))
                .unwrap();
            fw.SetEnabled(VARIANT_FALSE).unwrap();
        }
        let rule = FirewallRule {
            name: "Renamed".into(),
            description: "Changed".into(),
            enabled: true,
            local_ports: "70000".into(),
            ..Default::default()
        };
        assert!(update_existing_rule(&fw, "Original", &rule).is_err());
        assert!(!variant_to_bool(unsafe { fw.Enabled() }.unwrap()));
        assert_eq!(
            unsafe { fw.Description() }.unwrap().to_string(),
            "Original description"
        );
    }

    #[test]
    fn repeated_com_initialization_is_balanced() {
        std::thread::spawn(|| {
            let first = ComGuard::new().unwrap();
            let second = ComGuard::new().unwrap();
            drop(second);
            drop(first);
            assert!(
                unsafe { windows::Win32::System::Com::CoGetContextToken() }.is_err(),
                "Both S_OK and S_FALSE initializations must be balanced"
            );
        })
        .join()
        .unwrap();
    }
    // Detached NetFwRule objects: these tests never call policy.Rules().Add/Remove.
    #[test]
    fn renaming_preserves_existing_rule_and_advanced_properties() {
        let _com = ComGuard::new().unwrap();
        let fw = new_rule().unwrap();
        unsafe {
            fw.SetName(&BSTR::from("Original")).unwrap();
            fw.SetRemoteAddresses(&BSTR::from("10.0.0.0/8")).unwrap();
            fw.SetGrouping(&BSTR::from("Existing group")).unwrap();
        }
        let original_remote_addresses = unsafe { fw.RemoteAddresses() }.unwrap().to_string();
        let updated = FirewallRule {
            name: "Renamed".into(),
            local_ports: "22".into(),
            ..Default::default()
        };
        update_existing_rule(&fw, "Original", &updated).unwrap();
        unsafe {
            assert_eq!(fw.Name().unwrap().to_string(), "Renamed");
            assert_eq!(fw.Grouping().unwrap().to_string(), "Existing group");
            // Windows may normalize address formatting; compare the saved value.
            assert_eq!(
                fw.RemoteAddresses().unwrap().to_string(),
                original_remote_addresses
            );
        }
    }

    #[test]
    fn invalid_update_does_not_rename_or_delete_the_original_object() {
        let _com = ComGuard::new().unwrap();
        let fw = new_rule().unwrap();
        unsafe {
            fw.SetName(&BSTR::from("Original")).unwrap();
        }
        let updated = FirewallRule {
            name: "Renamed".into(),
            local_ports: "70000".into(),
            ..Default::default()
        };
        assert!(update_existing_rule(&fw, "Original", &updated).is_err());
        assert_eq!(unsafe { fw.Name() }.unwrap().to_string(), "Original");
    }

    #[test]
    fn invalid_text_is_rejected_before_other_properties_are_changed() {
        let _com = ComGuard::new().unwrap();
        let fw = new_rule().unwrap();
        unsafe {
            fw.SetName(&BSTR::from("Original")).unwrap();
            fw.SetEnabled(VARIANT_FALSE).unwrap();
        }
        let updated = FirewallRule {
            name: "bad|name".into(),
            enabled: true,
            local_ports: "22".into(),
            ..Default::default()
        };
        assert!(update_existing_rule(&fw, "Original", &updated).is_err());
        assert_eq!(unsafe { fw.Name() }.unwrap().to_string(), "Original");
        assert!(!variant_to_bool(unsafe { fw.Enabled() }.unwrap()));
    }
}
