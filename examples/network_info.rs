//! Read-only smoke check; prints counts without exposing local IP addresses.
fn main() {
    let adapters = firewall_windows::network::list_adapters().expect("read local adapters");
    let v4 = adapters
        .iter()
        .flat_map(|a| &a.addresses)
        .filter(|a| a.ip.is_ipv4())
        .count();
    let v6 = adapters
        .iter()
        .flat_map(|a| &a.addresses)
        .filter(|a| a.ip.is_ipv6())
        .count();
    println!(
        "Adapters: {}; IPv4 addresses: {v4}; IPv6 addresses: {v6}",
        adapters.len()
    );
}
