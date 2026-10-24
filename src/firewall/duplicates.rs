//! Полные условия правила и удаление одной копии при совпадающих именах.

use super::*;
use windows::Win32::NetworkManagement::WindowsFirewall::INetFwRule3;
use windows::Win32::System::Ole::{
    SafeArrayGetDim, SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound,
};
use windows::Win32::System::Variant::{VT_ARRAY, VT_BSTR, VT_EMPTY, VT_NULL, VT_VARIANT};

fn sorted_list(value: String) -> String {
    let mut parts: Vec<_> = value.split(',').map(|s| s.trim().to_lowercase()).collect();
    parts.sort();
    parts.dedup();
    parts.join(",")
}

/// Не подменять ошибку чтения пустым значением: такое правило исключается из дублей.
pub(super) fn comparison_key(fw: &INetFwRule) -> windows::core::Result<Vec<String>> {
    unsafe {
        let extended: INetFwRule3 = fw.cast()?;
        let protocol = fw.Protocol()?;
        let mut key = vec![
            fw.Direction()?.0.to_string(),
            fw.Action()?.0.to_string(),
            protocol.to_string(),
            fw.Profiles()?.to_string(),
            variant_to_bool(fw.Enabled()?).to_string(),
            fw.ApplicationName()?.to_string().to_lowercase(),
            fw.ServiceName()?.to_string().to_lowercase(),
            sorted_list(fw.LocalAddresses()?.to_string()),
            sorted_list(fw.RemoteAddresses()?.to_string()),
            sorted_list(fw.InterfaceTypes()?.to_string()),
            variant_to_bool(fw.EdgeTraversal()?).to_string(),
            extended.EdgeTraversalOptions()?.to_string(),
            extended.LocalAppPackageId()?.to_string(),
            extended.LocalUserOwner()?.to_string(),
            extended.LocalUserAuthorizedList()?.to_string(),
            extended.RemoteUserAuthorizedList()?.to_string(),
            extended.RemoteMachineAuthorizedList()?.to_string(),
            extended.SecureFlags()?.to_string(),
            fw.Grouping()?.to_string(),
        ];
        if protocol == 6 || protocol == 17 {
            key.push(sorted_list(fw.LocalPorts()?.to_string()));
            key.push(sorted_list(fw.RemotePorts()?.to_string()));
        } else if protocol == 1 || protocol == 58 {
            key.push(sorted_list(fw.IcmpTypesAndCodes()?.to_string()));
        }
        let mut interfaces = fw.Interfaces()?;
        let names = interface_names(&interfaces);
        let cleared = VariantClear(&mut interfaces);
        key.extend(names?);
        cleared?;
        Ok(key)
    }
}

fn interface_names(value: &VARIANT) -> windows::core::Result<Vec<String>> {
    unsafe {
        let vt = value.Anonymous.Anonymous.vt;
        if vt == VT_EMPTY || vt == VT_NULL {
            return Ok(Vec::new());
        }
        let bstr_array = vt.0 == (VT_ARRAY.0 | VT_BSTR.0);
        if !bstr_array && vt.0 != (VT_ARRAY.0 | VT_VARIANT.0) {
            return Err(windows::core::Error::from_hresult(windows::core::HRESULT(
                0x80070057u32 as i32,
            )));
        }
        let array = value.Anonymous.Anonymous.Anonymous.parray;
        if array.is_null() || SafeArrayGetDim(array) != 1 {
            return Err(windows::core::Error::from_hresult(windows::core::HRESULT(
                0x80070057u32 as i32,
            )));
        }
        let mut names = Vec::new();
        for index in SafeArrayGetLBound(array, 1)?..=SafeArrayGetUBound(array, 1)? {
            let name = if bstr_array {
                let mut text = BSTR::new();
                SafeArrayGetElement(array, &index, (&mut text as *mut BSTR).cast())?;
                text.to_string()
            } else {
                let mut item = VARIANT::default();
                SafeArrayGetElement(array, &index, (&mut item as *mut VARIANT).cast())?;
                let text = if item.Anonymous.Anonymous.vt == VT_BSTR {
                    Ok(item.Anonymous.Anonymous.Anonymous.bstrVal.to_string())
                } else {
                    Err(windows::core::Error::from_hresult(windows::core::HRESULT(
                        0x80070057u32 as i32,
                    )))
                };
                let cleared = VariantClear(&mut item);
                let text = text?;
                cleared?;
                text
            };
            names.push(name.to_lowercase());
        }
        names.sort();
        names.dedup();
        Ok(names)
    }
}

/// Проверяет снимок перед удалением. При одинаковых именах удаляет ровно одну
/// подходящую копию через временное уникальное имя, восстанавливая имя при ошибке.
pub fn remove_rule_snapshot(snapshot: &FirewallRule) -> Result<(), String> {
    let _com = ComGuard::new()?;
    let policy = policy()?;
    let rules = unsafe { policy.Rules() }.map_err(|e| map_com_err(e, "Rules"))?;
    let target = find_snapshot_rule(&rules, snapshot)?;
    let unique = format!(
        "FirewallManager_Delete_{:?}",
        unsafe { windows::Win32::System::Com::CoCreateGuid() }
            .map_err(|e| map_com_err(e, "CoCreateGuid"))?
    );
    delete_named_copy(
        &snapshot.name,
        &unique,
        |name| {
            unsafe { target.SetName(&BSTR::from(name)) }
                .map_err(|e| map_com_err(e, "Переименование для удаления"))
        },
        |name| unsafe { rules.Remove(&BSTR::from(name)) }.map_err(|e| map_com_err(e, "Remove")),
    )
}

pub(super) fn find_snapshot_rule(
    rules: &INetFwRules,
    snapshot: &FirewallRule,
) -> Result<INetFwRule, String> {
    let key = snapshot
        .comparison_key
        .as_ref()
        .ok_or("Не удалось прочитать все параметры правила. Обновите список")?;
    for rule in collect_com_rules(rules)? {
        let name = unsafe { rule.Name() }.map_err(|e| map_com_err(e, "Name"))?;
        if name == snapshot.name
            && comparison_key(&rule).ok().as_ref() == Some(key)
            && unsafe { rule.Description() }
                .ok()
                .is_some_and(|description| description == snapshot.description)
        {
            return Ok(rule);
        }
    }
    Err("Правило изменилось или уже удалено. Обновите список".into())
}

fn delete_named_copy(
    original: &str,
    unique: &str,
    mut rename: impl FnMut(&str) -> Result<(), String>,
    mut remove: impl FnMut(&str) -> Result<(), String>,
) -> Result<(), String> {
    rename(unique)?;
    if let Err(message) = remove(unique) {
        let restored = rename(original);
        return Err(match restored {
            Ok(()) => message,
            Err(e) => format!("{message}. Не удалось восстановить имя: {e}. Текущее имя: {unique}"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_arrays_are_sorted_and_distinguished_in_both_com_formats() {
        use windows::Win32::System::Ole::{SafeArrayCreateVector, SafeArrayPutElement};
        for element_type in [VT_BSTR, VT_VARIANT] {
            unsafe {
                let array = SafeArrayCreateVector(element_type, 3, 2);
                assert!(!array.is_null());
                let mut value = VARIANT::default();
                (*value.Anonymous.Anonymous).vt =
                    windows::Win32::System::Variant::VARENUM(VT_ARRAY.0 | element_type.0);
                (*value.Anonymous.Anonymous).Anonymous.parray = array;
                for (index, name) in [(3, "WiFi"), (4, "Ethernet")] {
                    let text = BSTR::from(name);
                    if element_type == VT_BSTR {
                        SafeArrayPutElement(array, &index, text.as_ptr().cast()).unwrap();
                    } else {
                        let mut item = VARIANT::default();
                        (*item.Anonymous.Anonymous).vt = VT_BSTR;
                        (*item.Anonymous.Anonymous).Anonymous.bstrVal =
                            std::mem::ManuallyDrop::new(text);
                        let inserted =
                            SafeArrayPutElement(array, &index, (&item as *const VARIANT).cast());
                        VariantClear(&mut item).unwrap();
                        inserted.unwrap();
                    }
                }
                let parsed = interface_names(&value);
                VariantClear(&mut value).unwrap();
                assert_eq!(parsed.unwrap(), vec!["ethernet", "wifi"]);
            }
        }
        assert!(interface_names(&VARIANT::default()).unwrap().is_empty());
    }

    fn tcp_rule() -> INetFwRule {
        let fw = new_rule().unwrap();
        apply_rule_props(
            &fw,
            &FirewallRule {
                name: "Test".into(),
                local_ports: "22".into(),
                ..Default::default()
            },
            true,
        )
        .unwrap();
        fw
    }

    #[test]
    fn native_comparison_checks_hidden_fields_and_ignores_name_and_description() {
        let _com = ComGuard::new().unwrap();
        let first = tcp_rule();
        let second = tcp_rule();
        let key = comparison_key(&first).unwrap();
        unsafe {
            second.SetName(&BSTR::from("Other name")).unwrap();
            second
                .SetDescription(&BSTR::from("Other description"))
                .unwrap();
        }
        assert_eq!(key, comparison_key(&second).unwrap());
        unsafe {
            second.SetRemoteAddresses(&BSTR::from("192.0.2.1")).unwrap();
        }
        assert_ne!(key, comparison_key(&second).unwrap());
        unsafe {
            second.SetRemoteAddresses(&BSTR::from("*")).unwrap();
            second.SetRemotePorts(&BSTR::from("443")).unwrap();
        }
        assert_ne!(key, comparison_key(&second).unwrap());
    }

    #[test]
    fn raw_icmp_protocols_and_profiles_are_not_confused() {
        let _com = ComGuard::new().unwrap();
        let first = new_rule().unwrap();
        let second = new_rule().unwrap();
        unsafe {
            first.SetProtocol(1).unwrap();
            second.SetProtocol(58).unwrap();
        }
        assert_ne!(
            comparison_key(&first).unwrap(),
            comparison_key(&second).unwrap()
        );
        unsafe {
            second.SetProtocol(1).unwrap();
            second.SetProfiles(2).unwrap();
        }
        assert_ne!(
            comparison_key(&first).unwrap(),
            comparison_key(&second).unwrap()
        );
    }

    #[test]
    fn deletion_targets_only_the_renamed_copy_and_leaves_its_twin() {
        use std::cell::RefCell;
        let names = RefCell::new(vec!["Same".to_string(), "Same".to_string()]);
        delete_named_copy(
            "Same",
            "Unique",
            |name| {
                names.borrow_mut()[1] = name.into();
                Ok(())
            },
            |name| {
                names.borrow_mut().retain(|n| n != name);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*names.borrow(), vec!["Same"]);
    }

    #[test]
    fn failed_deletion_restores_name_and_rename_failure_does_not_delete() {
        use std::cell::RefCell;
        let name = RefCell::new("Original".to_string());
        assert!(
            delete_named_copy(
                "Original",
                "Unique",
                |s| {
                    *name.borrow_mut() = s.into();
                    Ok(())
                },
                |_| Err("Removal denied".into())
            )
            .is_err()
        );
        assert_eq!(*name.borrow(), "Original");
        assert!(
            delete_named_copy(
                "Original",
                "Unique",
                |_| Err("Rename denied".into()),
                |_| panic!("Removal must not run after failed rename")
            )
            .is_err()
        );
        let error = delete_named_copy(
            "Original",
            "Unique",
            |s| {
                if s == "Original" {
                    Err("Restore denied".into())
                } else {
                    Ok(())
                }
            },
            |_| Err("Removal denied".into()),
        )
        .unwrap_err();
        assert!(error.contains("Unique") && error.contains("Restore denied"));
    }
}
