use num_derive::FromPrimitive;

#[derive(Clone)]
pub struct SpectreSettings {
    pub spectre_mitigation: SpectreMitigation,
    pub spectre_stop_sbx_breakout: bool,
    pub spectre_stop_sbx_poisoning: bool,
    pub spectre_stop_host_poisoning: bool,
    pub spectre_pht_mitigation: SpectrePHTMitigation,
    pub spectre_disable_btbflush: bool,
    pub spectre_disable_mpk: bool,
}

static mut SPECTRE_SETTINGS: SpectreSettings = SpectreSettings {
    spectre_mitigation: SpectreMitigation::NONE,
    spectre_stop_sbx_breakout: false,
    spectre_stop_sbx_poisoning: false,
    spectre_stop_host_poisoning: false,
    spectre_pht_mitigation: SpectrePHTMitigation::NONE,
    spectre_disable_btbflush: true,
    spectre_disable_mpk: true,
};

#[derive(PartialEq, Debug, Clone, Copy, FromPrimitive)]
pub enum SpectreMitigation {
    NONE,
    LOADLFENCE,
    STRAWMAN,
    SFI,
    CET,
    SFIASLR,
    CETASLR,
}

#[derive(PartialEq, Debug, Clone, Copy, FromPrimitive)]
pub enum SpectrePHTMitigation {
    NONE,
    BLADE,
    PHTTOBTB,
    INTERLOCK,
}

pub fn get_default_pht_protection(
    spectre_mitigation: SpectreMitigation,
    _spectre_stop_sbx_breakout: bool,
    spectre_stop_sbx_poisoning: bool,
    spectre_stop_host_poisoning: bool,
) -> SpectrePHTMitigation {
    if spectre_mitigation == SpectreMitigation::SFI && (spectre_stop_sbx_poisoning || spectre_stop_host_poisoning)
    {
        return SpectrePHTMitigation::PHTTOBTB;
    }
    else if spectre_mitigation == SpectreMitigation::CET && spectre_stop_sbx_poisoning
    {
        return SpectrePHTMitigation::INTERLOCK;
    }

    return SpectrePHTMitigation::NONE;
}

pub fn get_use_linear_block(spectre_mitigation: SpectreMitigation) -> bool {
    spectre_mitigation == SpectreMitigation::SFI ||
        spectre_mitigation == SpectreMitigation::CET ||
        spectre_mitigation == SpectreMitigation::SFIASLR ||
        spectre_mitigation == SpectreMitigation::CETASLR
}

pub fn use_spectre_mitigation_settings(
    spectre_mitigation: SpectreMitigation,
    spectre_stop_sbx_breakout: bool,
    spectre_stop_sbx_poisoning: bool,
    spectre_stop_host_poisoning: bool,
    spectre_pht_mitigation: SpectrePHTMitigation,
    spectre_disable_btbflush: bool,
    spectre_disable_mpk: bool,
) {
    unsafe {
        SPECTRE_SETTINGS = SpectreSettings {
            spectre_mitigation,
            spectre_stop_sbx_breakout,
            spectre_stop_sbx_poisoning,
            spectre_stop_host_poisoning,
            spectre_pht_mitigation,
            spectre_disable_btbflush,
            spectre_disable_mpk,
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
pub fn get_spectre_stop_sbx_breakout() -> bool {
    unsafe {
        return SPECTRE_SETTINGS.spectre_stop_sbx_breakout.clone();
    }
}
#[inline(always)]
pub fn get_spectre_stop_sbx_poisoning() -> bool {
    unsafe {
        return SPECTRE_SETTINGS.spectre_stop_sbx_poisoning.clone();
    }
}
#[inline(always)]
pub fn get_spectre_stop_host_poisoning() -> bool {
    unsafe {
        return SPECTRE_SETTINGS.spectre_stop_host_poisoning.clone();
    }
}

#[inline(always)]
pub fn get_spectre_pht_mitigation() -> SpectrePHTMitigation {
    unsafe {
        return SPECTRE_SETTINGS.spectre_pht_mitigation.clone();
    }
}

#[inline(always)]
pub fn get_spectre_disable_btbflush() -> bool {
    unsafe {
        return SPECTRE_SETTINGS.spectre_disable_btbflush.clone();
    }
}

#[inline(always)]
pub fn get_spectre_disable_mpk() -> bool {
    unsafe {
        return SPECTRE_SETTINGS.spectre_disable_mpk.clone();
    }
}
