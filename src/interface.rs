use anyhow::Context as _;

fn ifreq_for(name: &str) -> anyhow::Result<libc::ifreq> {
    let mut request = libc::ifreq {
        ifr_name: [0; libc::IF_NAMESIZE],
        ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_ifindex: 0 },
    };

    for (i, byte) in name.as_bytes().iter().enumerate() {
        *request
            .ifr_name
            .get_mut(i)
            .context("interface name is too long")? = *byte as libc::c_char
    }
    Ok(request)
}

pub fn ifindex_for(fd: libc::c_int, name: &str) -> anyhow::Result<libc::c_int> {
    let mut request = ifreq_for(name)?;
    let res = unsafe { libc::ioctl(fd, libc::SIOCGIFINDEX as _, &mut request) };
    if res < 0 {
        anyhow::bail!(
            "failed to get interface index: {}",
            std::io::Error::last_os_error()
        );
    }

    Ok(unsafe { request.ifr_ifru.ifru_ifindex })
}

pub fn ifhwaddr_for(fd: libc::c_int, name: &str) -> anyhow::Result<libc::sockaddr> {
    let mut request = ifreq_for(name)?;
    let res = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR as _, &mut request) };
    if res < 0 {
        anyhow::bail!(
            "failed to get interface hardware address: {}",
            std::io::Error::last_os_error()
        );
    }

    Ok(unsafe { request.ifr_ifru.ifru_hwaddr })
}
