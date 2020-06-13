use crate::settings::{SpectreMitigation, SpectrePHTMitigation, SpectreSettings};
use std::cell::RefCell;
use std::thread_local;

pub const CFI_START_FUNC_LABEL: u64 = 10;

thread_local! {
    static SPECTRE_RUNTIME_SETTINGS: RefCell<SpectreSettings> = RefCell::new(SpectreSettings {
        spectre_mitigation: SpectreMitigation::NONE,
        spectre_stop_sbx_breakout: false,
        spectre_stop_sbx_poisoning: false,
        spectre_stop_host_poisoning: false,
        spectre_pht_mitigation: SpectrePHTMitigation::NONE,
        spectre_disable_btbflush: true,
    });
}

pub fn use_spectre_mitigation_runtime_settings(
    settings: SpectreSettings,
) {
    SPECTRE_RUNTIME_SETTINGS.with(|spectre_runtime_settings|{
        *spectre_runtime_settings.borrow_mut() = settings;
    });
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
pub fn perform_transition_protection_in() {
    // Hack: In an actual implementation, this if condition is bad. You would want to do this unconditionally or with cmovs
    // But that's just engineering work
    let mitigation = get_spectre_mitigation();
    if mitigation != SpectreMitigation::NONE {
        unsafe {
            invoke_lfence();
        }

        if mitigation == SpectreMitigation::SFI && !get_spectre_disable_btbflush() &&
            (get_spectre_stop_sbx_breakout() || get_spectre_stop_sbx_poisoning())
        {
            unsafe {
                btb_flush();
            }
        }
    }
}

#[inline(always)]
pub fn perform_transition_protection_out() {
    // Hack: In an actual implementation, this if condition is bad. You would want to do this unconditionally or with cmovs
    // But that's just engineering work
    let mitigation = get_spectre_mitigation();
    if mitigation != SpectreMitigation::NONE {
        unsafe {
            invoke_lfence();
        }

        if mitigation == SpectreMitigation::SFI && !get_spectre_disable_btbflush() &&
            get_spectre_stop_host_poisoning()
        {
            unsafe {
                btb_flush();
            }
        }
    }
}
