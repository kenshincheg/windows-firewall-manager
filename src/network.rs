//! Local adapter inventory, without shell processes or requests to external hosts.

use std::mem::{MaybeUninit, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkAddress {
    pub ip: IpAddr,
    pub prefix_len: u8,
    pub scope_id: u32,
}

impl NetworkAddress {
    pub fn display(&self) -> String {
        let mut value = self.ip.to_string();
        if self.ip.is_ipv6() && self.scope_id != 0 {
            value.push_str(&format!("%{}", self.scope_id));
        }
        if self.prefix_len <= if self.ip.is_ipv4() { 32 } else { 128 } {
            value.push_str(&format!("/{}", self.prefix_len));
        }
        value
    }
}

#[derive(Clone, Debug)]
pub struct NetworkAdapter {
    pub name: String,
    pub description: String,
    pub kind: &'static str,
    pub status: &'static str,
    pub is_up: bool,
    pub is_loopback: bool,
    pub addresses: Vec<NetworkAddress>,
}

/// Synchronous API: callers run this on a worker thread, never during UI painting.
/// https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
pub fn list_adapters() -> Result<Vec<NetworkAdapter>, String> {
    let mut bytes = 15_000_u32;
    for _ in 0..4 {
        // The buffer must be aligned for the linked native structures it holds.
        let count = (bytes as usize).div_ceil(size_of::<IP_ADAPTER_ADDRESSES_LH>());
        let mut storage = Vec::<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>::with_capacity(count);
        storage.resize_with(count, MaybeUninit::uninit);
        let head = storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let code = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_SKIP_ANYCAST
                    | GAA_FLAG_SKIP_MULTICAST
                    | GAA_FLAG_SKIP_DNS_SERVER
                    | GAA_FLAG_INCLUDE_ALL_INTERFACES,
                None,
                Some(head),
                &mut bytes,
            )
        };
        if code == ERROR_BUFFER_OVERFLOW.0 {
            continue;
        }
        if code == ERROR_NO_DATA.0 {
            return Ok(Vec::new());
        }
        if code != NO_ERROR.0 {
            return Err(format!(
                "Не удалось получить сетевые адаптеры (код Windows {code})"
            ));
        }
        let mut result = Vec::new();
        // All linked pointers and strings belong to storage, which stays alive
        // until this traversal finishes. Copy data out before dropping storage.
        unsafe {
            let mut current = head;
            while let Some(adapter) = current.as_ref() {
                let name = if adapter.FriendlyName.is_null() {
                    String::new()
                } else {
                    adapter.FriendlyName.to_string().unwrap_or_default()
                };
                let description = if adapter.Description.is_null() {
                    String::new()
                } else {
                    adapter.Description.to_string().unwrap_or_default()
                };
                let mut addresses = Vec::new();
                let mut address = adapter.FirstUnicastAddress;
                while let Some(unicast) = address.as_ref() {
                    if let Some(value) = read_address(&unicast.Address, unicast.OnLinkPrefixLength)
                    {
                        addresses.push(value);
                    }
                    address = unicast.Next;
                }
                addresses.sort();
                addresses.dedup();
                result.push(NetworkAdapter {
                    name: if name.is_empty() {
                        description.clone()
                    } else {
                        name
                    },
                    description,
                    kind: match adapter.IfType {
                        IF_TYPE_ETHERNET_CSMACD => "Ethernet",
                        IF_TYPE_IEEE80211 => "Wi-Fi",
                        IF_TYPE_SOFTWARE_LOOPBACK => "Loopback",
                        IF_TYPE_TUNNEL => "Туннель",
                        _ => "Сетевой адаптер",
                    },
                    status: match adapter.OperStatus.0 {
                        1 => "Подключён",
                        2 => "Отключён",
                        3 => "Проверка",
                        5 => "Ожидание",
                        6 => "Не подключён",
                        7 => "Нет связи с нижним уровнем",
                        _ => "Статус неизвестен",
                    },
                    is_up: adapter.OperStatus == IfOperStatusUp,
                    is_loopback: adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK,
                    addresses,
                });
                current = adapter.Next;
            }
        }
        result.sort_by_key(|a| (a.is_loopback, !a.is_up, a.name.to_lowercase()));
        return Ok(result);
    }
    Err("Сетевая конфигурация меняется. Повторите обновление.".into())
}

/// `address` must point to a live native socket-address buffer of the stated size.
unsafe fn read_address(address: &SOCKET_ADDRESS, prefix_len: u8) -> Option<NetworkAddress> {
    if address.lpSockaddr.is_null() || address.iSockaddrLength < size_of::<u16>() as i32 {
        return None;
    }
    let family = unsafe { address.lpSockaddr.cast::<u16>().read_unaligned() };
    if family == AF_INET.0 && address.iSockaddrLength >= size_of::<SOCKADDR_IN>() as i32 {
        let value = unsafe { address.lpSockaddr.cast::<SOCKADDR_IN>().read_unaligned() };
        Some(NetworkAddress {
            ip: IpAddr::V4(Ipv4Addr::from(
                unsafe { value.sin_addr.S_un.S_addr }.to_ne_bytes(),
            )),
            prefix_len,
            scope_id: 0,
        })
    } else if family == AF_INET6.0 && address.iSockaddrLength >= size_of::<SOCKADDR_IN6>() as i32 {
        let value = unsafe { address.lpSockaddr.cast::<SOCKADDR_IN6>().read_unaligned() };
        Some(NetworkAddress {
            ip: IpAddr::V6(Ipv6Addr::from(unsafe { value.sin6_addr.u.Byte })),
            prefix_len,
            scope_id: unsafe { value.Anonymous.sin6_scope_id },
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_bytes_and_prefix_are_preserved() {
        let mut value = SOCKADDR_IN::default();
        value.sin_family = AF_INET;
        value.sin_addr.S_un.S_addr = u32::from_ne_bytes([192, 168, 12, 34]);
        let address = SOCKET_ADDRESS {
            lpSockaddr: (&mut value as *mut SOCKADDR_IN).cast(),
            iSockaddrLength: size_of::<SOCKADDR_IN>() as i32,
        };
        assert_eq!(
            unsafe { read_address(&address, 24) }.unwrap().display(),
            "192.168.12.34/24"
        );
        assert!(
            unsafe {
                read_address(
                    &SOCKET_ADDRESS {
                        iSockaddrLength: 2,
                        ..address
                    },
                    24,
                )
            }
            .is_none()
        );
    }

    #[test]
    fn ipv6_scope_is_kept_and_multiple_addresses_survive() {
        let mut value = SOCKADDR_IN6::default();
        value.sin6_family = AF_INET6;
        value.sin6_addr.u.Byte = "fe80::1234".parse::<Ipv6Addr>().unwrap().octets();
        value.Anonymous.sin6_scope_id = 17;
        let socket = SOCKET_ADDRESS {
            lpSockaddr: (&mut value as *mut SOCKADDR_IN6).cast(),
            iSockaddrLength: size_of::<SOCKADDR_IN6>() as i32,
        };
        let v6 = unsafe { read_address(&socket, 64) }.unwrap();
        assert_eq!(v6.display(), "fe80::1234%17/64");
        let v4 = NetworkAddress {
            ip: "10.0.0.2".parse().unwrap(),
            prefix_len: 24,
            scope_id: 0,
        };
        let mut addresses = vec![
            v6.clone(),
            v4.clone(),
            v6,
            NetworkAddress {
                ip: "10.0.0.3".parse().unwrap(),
                ..v4
            },
        ];
        addresses.sort();
        addresses.dedup();
        assert_eq!(addresses.len(), 3);
        assert!(addresses[0].ip.is_ipv4());
        assert!(addresses[2].ip.is_ipv6());
    }
}
