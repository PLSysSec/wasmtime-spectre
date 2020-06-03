use num_derive::FromPrimitive;

#[derive(Clone)]
pub struct SpectreSettings {
    pub spectre_mitigation: SpectreMitigation,
    pub spectre_pht_mitigation: SpectrePHTMitigation,
    pub spectre_only_sandbox_isolation: bool,
    pub spectre_no_cross_sbx_attacks: bool,
    pub spectre_disable_core_switching: bool,
    pub spectre_disable_btbflush: bool,
}

static mut SPECTRE_SETTINGS: SpectreSettings = SpectreSettings {
    spectre_mitigation: SpectreMitigation::NONE,
    spectre_pht_mitigation: SpectrePHTMitigation::NONE,
    spectre_only_sandbox_isolation: false,
    spectre_no_cross_sbx_attacks: false,
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
    PHTTOBTB
}

pub fn get_default_pht_protection(
    spectre_mitigation: Option<SpectreMitigation>,
    spectre_only_sandbox_isolation: bool,
    spectre_no_cross_sbx_attacks: bool,
) -> Option<SpectrePHTMitigation> {
    if spectre_mitigation.is_none() || spectre_only_sandbox_isolation || spectre_no_cross_sbx_attacks {
        return Some(SpectrePHTMitigation::NONE);
    }

    let spectre_mitigation = spectre_mitigation.unwrap();
    if spectre_mitigation == SpectreMitigation::SFI
    {
        return Some(SpectrePHTMitigation::PHTTOBTB);
    }
    else if spectre_mitigation == SpectreMitigation::CET
    {
        return Some(SpectrePHTMitigation::BLADE);
    }

    return Some(SpectrePHTMitigation::NONE);
}


pub fn use_spectre_mitigation_settings(
    spectre_mitigation: Option<SpectreMitigation>,
    spectre_pht_mitigation: Option<SpectrePHTMitigation>,
    spectre_only_sandbox_isolation: bool,
    spectre_no_cross_sbx_attacks: bool,
    spectre_disable_core_switching: bool,
    spectre_disable_btbflush: bool,
) {
    let spectre_mitigation = spectre_mitigation.unwrap_or(get_spectre_mitigation());
    let spectre_pht_mitigation = spectre_pht_mitigation.unwrap_or(get_spectre_pht_mitigation());
    unsafe {
        SPECTRE_SETTINGS = SpectreSettings {
            spectre_mitigation,
            spectre_pht_mitigation,
            spectre_only_sandbox_isolation,
            spectre_no_cross_sbx_attacks,
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
pub fn get_spectre_no_cross_sbx_attacks() -> bool {
    unsafe {
        return SPECTRE_SETTINGS.spectre_no_cross_sbx_attacks.clone();
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
