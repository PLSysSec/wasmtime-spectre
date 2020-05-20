use num_derive::FromPrimitive;

#[derive(Clone)]
struct SpectreSettings {
    spectre_mitigation: SpectreMitigation,
    spectre_pht_mitigation: SpectrePHTMitigation,
    spectre_only_sandbox_isolation: bool,
}

static mut SPECTRE_SETTINGS: SpectreSettings = SpectreSettings {
    spectre_mitigation: SpectreMitigation::NONE,
    spectre_pht_mitigation: SpectrePHTMitigation::NONE,
    spectre_only_sandbox_isolation: false,
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

pub fn use_spectre_mitigation_settings(
    spectre_mitigation: Option<SpectreMitigation>,
    spectre_pht_mitigation: Option<SpectrePHTMitigation>,
    spectre_only_sandbox_isolation: bool,
) {
    let spectre_mitigation = spectre_mitigation.unwrap_or(get_spectre_mitigation());
    let spectre_pht_mitigation = spectre_pht_mitigation.unwrap_or(get_spectre_pht_mitigation());

    unsafe {
        SPECTRE_SETTINGS = SpectreSettings {
            spectre_mitigation,
            spectre_pht_mitigation,
            spectre_only_sandbox_isolation,
        };
    }
}

pub fn get_spectre_mitigation() -> SpectreMitigation {
    unsafe {
        return SPECTRE_SETTINGS.spectre_mitigation.clone();
    }
}

pub fn get_spectre_pht_mitigation() -> SpectrePHTMitigation {
    unsafe {
        return SPECTRE_SETTINGS.spectre_pht_mitigation.clone();
    }
}

pub fn get_spectre_only_sandbox_isolation() -> bool {
    unsafe {
        return SPECTRE_SETTINGS.spectre_only_sandbox_isolation.clone();
    }
}
