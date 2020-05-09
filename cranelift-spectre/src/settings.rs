#[derive(Clone)]
struct SpectreSettings {
    spectre_mitigation: SpectreMitigation,
    spectre_pht_mitigation: SpectrePHTMitigation,
}

static mut SPECTRE_SETTINGS: SpectreSettings = SpectreSettings {
    spectre_mitigation: SpectreMitigation::NONE,
    spectre_pht_mitigation: SpectrePHTMitigation::NONE,
};

#[derive(PartialEq, Debug, Clone)]
pub enum SpectreMitigation {
    NONE,
    LOADLFENCE,
    STRAWMAN,
    SFI,
    CET,
}

#[derive(PartialEq, Debug, Clone)]
pub enum SpectrePHTMitigation {
    NONE,
    BLADE,
}

pub fn use_spectre_mitigation_settings(
    spectre_mitigation: Option<SpectreMitigation>,
    spectre_pht_mitigation: Option<SpectrePHTMitigation>,
) {
    let spectre_mitigation = spectre_mitigation.unwrap_or(get_spectre_mitigation());
    let spectre_pht_mitigation = spectre_pht_mitigation.unwrap_or(get_spectre_pht_mitigation());

    unsafe {
        SPECTRE_SETTINGS = SpectreSettings {
            spectre_mitigation,
            spectre_pht_mitigation,
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
