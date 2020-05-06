#[derive(Clone)]
struct SpectreSettings {
    spectre_mitigation: SpectreMitigation,
}

static mut SPECTRE_SETTINGS: SpectreSettings = SpectreSettings {
    spectre_mitigation: SpectreMitigation::NONE,
};

#[derive(PartialEq, Debug, Clone)]
pub enum SpectreMitigation {
    NONE,
    LOADLFENCE,
    STRAWMAN,
    SFI,
    CET,
}

pub fn use_spectre_mitigation_settings(spectre_mitigation: Option<SpectreMitigation>) {
    let spectre_mitigation = spectre_mitigation.unwrap_or(get_spectre_mitigation());

    unsafe {
        SPECTRE_SETTINGS = SpectreSettings { spectre_mitigation };
    }
}

pub fn get_spectre_mitigation() -> SpectreMitigation {
    unsafe {
        return SPECTRE_SETTINGS.spectre_mitigation.clone();
    }
}
