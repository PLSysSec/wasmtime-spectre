use num_derive::FromPrimitive;
use std::mem::MaybeUninit;

#[derive(Clone)]
struct SpectreSettings {
    spectre_mitigation: SpectreMitigation,
    spectre_pht_mitigation: SpectrePHTMitigation,
    spectre_only_sandbox_isolation: bool,
    spectre_disable_core_switching: bool,
    spectre_disable_btbflush: bool,
}

static mut SPECTRE_SETTINGS: SpectreSettings = SpectreSettings {
    spectre_mitigation: SpectreMitigation::NONE,
    spectre_pht_mitigation: SpectrePHTMitigation::NONE,
    spectre_only_sandbox_isolation: false,
    spectre_disable_core_switching: false,
    spectre_disable_btbflush: false,
};

#[derive(PartialEq, Debug, Clone, Copy, FromPrimitive)]
pub enum SpectreMitigation {
    NONE,
    LOADLFENCE,
    STRAWMAN,
    SFI,
    CET,
}

#[derive(PartialEq, Debug, Clone, Copy, FromPrimitive)]
pub enum SpectrePHTMitigation {
    NONE,
    BLADE,
}

pub fn get_default_pht_protection(
    spectre_mitigation: Option<SpectreMitigation>,
    spectre_only_sandbox_isolation: bool,
) -> Option<SpectrePHTMitigation> {
    if spectre_mitigation.is_none() || spectre_only_sandbox_isolation {
        return Some(SpectrePHTMitigation::NONE);
    }

    let spectre_mitigation = spectre_mitigation.unwrap();
    if spectre_mitigation == SpectreMitigation::SFI || spectre_mitigation == SpectreMitigation::CET
    {
        return Some(SpectrePHTMitigation::BLADE);
    }

    return Some(SpectrePHTMitigation::NONE);
}

pub static mut APPLICATION_CPUS: Option<libc::cpu_set_t> = None;
pub static mut SANDBOX_CPUS: Option<libc::cpu_set_t> = None;

pub fn use_spectre_mitigation_settings(
    spectre_mitigation: Option<SpectreMitigation>,
    spectre_pht_mitigation: Option<SpectrePHTMitigation>,
    spectre_only_sandbox_isolation: bool,
    spectre_disable_core_switching: bool,
    spectre_disable_btbflush: bool,
) {
    let spectre_mitigation = spectre_mitigation.unwrap_or(get_spectre_mitigation());
    let spectre_pht_mitigation = spectre_pht_mitigation.unwrap_or(get_spectre_pht_mitigation());

    unsafe{
        let cpu_count = sysconf::raw::sysconf(sysconf::SysconfVariable::ScNprocessorsOnln).unwrap() as usize;
        let mut cpuset = MaybeUninit::uninit().assume_init();
        libc::CPU_ZERO(&mut cpuset);
        for i in 1..cpu_count {
            libc::CPU_SET(i, &mut cpuset);
        }
        APPLICATION_CPUS = Some(cpuset);

        let mut cpuset = MaybeUninit::uninit().assume_init();
        libc::CPU_ZERO(&mut cpuset);
        libc::CPU_SET(0, &mut cpuset);
        SANDBOX_CPUS = Some(cpuset);
    }
    unsafe {
        SPECTRE_SETTINGS = SpectreSettings {
            spectre_mitigation,
            spectre_pht_mitigation,
            spectre_only_sandbox_isolation,
            spectre_disable_core_switching,
            spectre_disable_btbflush,
        };
    }
}

#[inline(always)]
pub fn get_spectre_mitigation() -> SpectreMitigation {
    unsafe {
        return SPECTRE_SETTINGS.spectre_mitigation.clone();
    }
}

#[inline(always)]
pub fn get_spectre_pht_mitigation() -> SpectrePHTMitigation {
    unsafe {
        return SPECTRE_SETTINGS.spectre_pht_mitigation.clone();
    }
}

#[inline(always)]
pub fn get_spectre_only_sandbox_isolation() -> bool {
    unsafe {
        return SPECTRE_SETTINGS.spectre_only_sandbox_isolation.clone();
    }
}

#[inline(always)]
pub fn get_spectre_disable_core_switching() -> bool {
    unsafe {
        return SPECTRE_SETTINGS.spectre_disable_core_switching.clone();
    }
}

#[inline(always)]
pub fn get_spectre_disable_btbflush() -> bool {
    unsafe {
        return SPECTRE_SETTINGS.spectre_disable_btbflush.clone();
    }
}
