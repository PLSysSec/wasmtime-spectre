use crate::settings::{SpectreMitigation, SpectrePHTMitigation, SpectreSettings};
use std::cell::RefCell;
use std::thread_local;

pub const CFI_START_FUNC_LABEL: u64 = 10;

struct SpectreTransitionSettings {
    pub should_lfence_in: bool,
    pub should_lfence_out: bool,
    pub should_flush_in: bool,
    pub should_flush_out: bool,
}

thread_local! {
    static SPECTRE_RUNTIME_SETTINGS: RefCell<SpectreSettings> = RefCell::new(SpectreSettings {
        spectre_mitigation: SpectreMitigation::NONE,
        spectre_stop_sbx_breakout: false,
        spectre_stop_sbx_poisoning: false,
        spectre_stop_host_poisoning: false,
        spectre_pht_mitigation: SpectrePHTMitigation::NONE,
        spectre_disable_btbflush: true,
    });

    static SPECTRE_TRANSITION_SETTINGS: RefCell<SpectreTransitionSettings> = RefCell::new(SpectreTransitionSettings {
        should_lfence_in : false,
        should_lfence_out : false,
        should_flush_in : false,
        should_flush_out : false,
    });
}

fn update_transition_settings() {
    let mitigation = get_spectre_mitigation();
    let should_lfence_in = mitigation != SpectreMitigation::NONE;
    let should_lfence_out = should_lfence_in;
    let should_flush_in =
        if get_spectre_disable_btbflush() {
            false
        } else {
            if mitigation == SpectreMitigation::SFIASLR ||  mitigation == SpectreMitigation::SFI {
                get_spectre_stop_sbx_breakout() || get_spectre_stop_sbx_poisoning()
            } else if mitigation == SpectreMitigation::CETASLR {
                get_spectre_stop_sbx_poisoning()
            } else {
                false
            }
        };
    let should_flush_out =
        if get_spectre_disable_btbflush() {
            false
        } else {
            if mitigation == SpectreMitigation::SFIASLR || mitigation == SpectreMitigation::SFI {
                get_spectre_stop_host_poisoning()
            } else {
                false
            }
        };

    let transition_settings = SpectreTransitionSettings {
        should_lfence_in,
        should_lfence_out,
        should_flush_in,
        should_flush_out,
    };
    SPECTRE_TRANSITION_SETTINGS.with(|spectre_transition_settings|{
        *spectre_transition_settings.borrow_mut() = transition_settings;
    });
}

pub fn use_spectre_mitigation_runtime_settings(
    settings: SpectreSettings,
) {
    SPECTRE_RUNTIME_SETTINGS.with(|spectre_runtime_settings|{
        *spectre_runtime_settings.borrow_mut() = settings;
    });

    update_transition_settings();
}

extern "C" {
    fn btb_flush();
    fn invoke_lfence();
}

#[inline(always)]
pub fn get_spectre_mitigation() -> SpectreMitigation {
    SPECTRE_RUNTIME_SETTINGS.with(|spectre_runtime_settings|{
        return spectre_runtime_settings.borrow().spectre_mitigation.clone();
    })
}

#[inline(always)]
pub fn get_spectre_stop_sbx_breakout() -> bool {
    SPECTRE_RUNTIME_SETTINGS.with(|spectre_runtime_settings|{
        return spectre_runtime_settings.borrow().spectre_stop_sbx_breakout.clone();
    })
}
#[inline(always)]
pub fn get_spectre_stop_sbx_poisoning() -> bool {
    SPECTRE_RUNTIME_SETTINGS.with(|spectre_runtime_settings|{
        return spectre_runtime_settings.borrow().spectre_stop_sbx_poisoning.clone();
    })
}
#[inline(always)]
pub fn get_spectre_stop_host_poisoning() -> bool {
    SPECTRE_RUNTIME_SETTINGS.with(|spectre_runtime_settings|{
        return spectre_runtime_settings.borrow().spectre_stop_host_poisoning.clone();
    })
}

#[inline(always)]
pub fn get_spectre_pht_mitigation() -> SpectrePHTMitigation {
    SPECTRE_RUNTIME_SETTINGS.with(|spectre_runtime_settings|{
        return spectre_runtime_settings.borrow().spectre_pht_mitigation.clone();
    })
}

#[inline(always)]
pub fn get_spectre_disable_btbflush() -> bool {
    SPECTRE_RUNTIME_SETTINGS.with(|spectre_runtime_settings|{
        return spectre_runtime_settings.borrow().spectre_disable_btbflush.clone();
    })
}

#[inline(always)]
pub fn get_should_lfence_in() -> bool {
    SPECTRE_TRANSITION_SETTINGS.with(|spectre_transition_settings|{
        return spectre_transition_settings.borrow().should_lfence_in;
    })
}
#[inline(always)]
pub fn get_should_lfence_out() -> bool {
    SPECTRE_TRANSITION_SETTINGS.with(|spectre_transition_settings|{
        return spectre_transition_settings.borrow().should_lfence_out;
    })
}
#[inline(always)]
pub fn get_should_flush_in() -> bool {
    SPECTRE_TRANSITION_SETTINGS.with(|spectre_transition_settings|{
        return spectre_transition_settings.borrow().should_flush_in;
    })
}
#[inline(always)]
pub fn get_should_flush_out() -> bool {
    SPECTRE_TRANSITION_SETTINGS.with(|spectre_transition_settings|{
        return spectre_transition_settings.borrow().should_flush_out;
    })
}

#[inline(always)]
pub fn perform_transition_protection_in() {
    // Hack: In an actual implementation, this if condition is bad. You would want to do this unconditionally or with cmovs
    // But that's just engineering work
    if get_should_lfence_in() {
        unsafe {
            invoke_lfence();
        }
    }

    if get_should_flush_in() {
        unsafe {
            btb_flush();
        }
    }
}

#[inline(always)]
pub fn perform_transition_protection_out() {
    // Hack: In an actual implementation, this if condition is bad. You would want to do this unconditionally or with cmovs
    // But that's just engineering work
    if get_should_lfence_out() {
        unsafe {
            invoke_lfence();
        }
    }

    if get_should_flush_out() {
        unsafe {
            btb_flush();
        }
    }
}
